package veil

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	rand2 "math/rand"

	"github.com/agl/ed25519/extra25519"
)

type PublicKey []byte

type PrivateKey []byte

func GenerateKeys() (PublicKey, PrivateKey, error) {
	var privateKey, representative, publicKey [32]byte
	for {
		// generate a random secret key
		_, err := io.ReadFull(rand.Reader, privateKey[:])
		if err != nil {
			return nil, nil, err
		}

		// check if it maps to a valid Elligator2 representative
		if extra25519.ScalarBaseMult(&publicKey, &representative, &privateKey) {
			// use the representative as the public key
			return representative[:], privateKey[:], nil
		}
	}
}

const (
	digestLen          = 32
	headerLen          = demKeyLen + 8 + 8 + digestLen
	encryptedHeaderLen = headerLen + kemOverhead
)

func Encrypt(recipients []PublicKey, plaintext []byte, padding, fakes int) ([]byte, error) {
	// add fake recipients
	recipients, err := addFakes(recipients, fakes)
	if err != nil {
		return nil, err
	}

	// generate a data encapsulation key
	session := make([]byte, demKeyLen)
	_, err = io.ReadFull(rand.Reader, session)
	if err != nil {
		return nil, err
	}

	// encode session key, offset, size, and digest into a header
	header := encodeHeader(session, len(recipients), plaintext)

	// write KEM-encrypted copies of the header
	buf := bytes.NewBuffer(nil)
	fake := make([]byte, headerLen+kemOverhead)
	for _, public := range recipients {
		if public == nil {
			// write a random fake header
			_, err = io.ReadFull(rand.Reader, fake)
			if err != nil {
				return nil, err
			}
			buf.Write(fake)
		} else {
			// write an actual header
			b, err := kemEncrypt(public, header)
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
	}

	// pad the plaintext with random data
	padded := make([]byte, len(plaintext)+padding)
	copy(padded[:len(plaintext)], plaintext)
	_, err = io.ReadFull(rand.Reader, padded[len(plaintext):])
	if err != nil {
		return nil, err
	}

	// encrypt padded plaintext with the session key, using the encrypted headers as AD
	ciphertext, err := demEncrypt(session, padded, buf.Bytes())
	if err != nil {
		return nil, err
	}
	buf.Write(ciphertext)

	// return encrypted headers + encrypted padded plaintext
	return buf.Bytes(), nil
}

func Decrypt(private PrivateKey, public PublicKey, ciphertext []byte) ([]byte, error) {
	r := bytes.NewReader(ciphertext)

	// look for decryptable header
	encryptedHeader := make([]byte, encryptedHeaderLen)
	dek := make([]byte, demKeyLen)
	var offset, size uint64
	digest := make([]byte, digestLen)
	for {
		// read a header's worth of data
		_, err := io.ReadFull(r, encryptedHeader)
		if err == io.EOF {
			return nil, errors.New("invalid ciphertext")
		} else if err != nil {
			return nil, err
		}

		// try to decrypt it
		header, err := kemDecrypt(private, public, encryptedHeader)
		if err == nil {
			// if we can decrypt it, read the data encapsulation key, offset, size, and digest
			r := bytes.NewReader(header)
			_, _ = io.ReadFull(r, dek)
			_ = binary.Read(r, binary.BigEndian, &offset)
			_ = binary.Read(r, binary.BigEndian, &size)
			_, _ = io.ReadFull(r, digest)
			break
		}
	}

	// decrypt padded plaintext
	padded, err := demDecrypt(dek, ciphertext[offset:], ciphertext[:offset])
	if err != nil {
		return nil, err
	}

	// strip padding and verify plaintext
	plaintext := padded[:size]
	if subtle.ConstantTimeCompare(digest, sha512t256(plaintext)) == 0 {
		return nil, errors.New("invalid ciphertext")
	}
	return plaintext, nil
}

func encodeHeader(session []byte, recipients int, plaintext []byte) []byte {
	header := bytes.NewBuffer(nil)
	header.Write(session)
	_ = binary.Write(header, binary.BigEndian, uint64(encryptedHeaderLen*recipients))
	_ = binary.Write(header, binary.BigEndian, uint64(len(plaintext)))
	header.Write(sha512t256(plaintext))
	return header.Bytes()
}

func sha512t256(plaintext []byte) []byte {
	h := sha512.New512_256()
	h.Write(plaintext)
	return h.Sum(nil)
}

func addFakes(recipients []PublicKey, fakes int) ([]PublicKey, error) {
	out := make([]PublicKey, len(recipients)+fakes)
	copy(out, recipients)
	seed, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	r := rand2.New(rand2.NewSource(seed.Int64()))
	r.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})
	return out, nil
}

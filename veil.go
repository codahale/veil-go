// Package veil provides an implementation of the Veil hybrid cryptosystem.
package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	rand2 "math/rand"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/ed25519"
)

// GenerateKeys generates an X25519 key pair and returns the Elligator2 representative of the public
// key and the private key.
func GenerateKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	for {
		// generate an Ed25519 key pair
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		// convert the private key to X25519
		var edPrivate [64]byte
		copy(edPrivate[:], private)
		var xPrivate [32]byte
		extra25519.PrivateKeyToCurve25519(&xPrivate, &edPrivate)

		// check if it maps to a valid Elligator2 representative
		var representative, publicKey [32]byte
		if extra25519.ScalarBaseMult(&publicKey, &representative, &xPrivate) {
			return public, private, nil
		}
	}
}

const (
	headerLen          = demKeyLen + 8 + 8
	encryptedHeaderLen = headerLen + kemOverhead
	sigLen             = 64
)

// Encrypt returns a Veil ciphertext containing the given plaintext, decryptable by the given
// recipients, with the given number of random padding bytes and fake recipients.
func Encrypt(sender ed25519.PrivateKey, recipients []ed25519.PublicKey, plaintext []byte, padding, fakes int) ([]byte, error) {
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

	// sign the padded plaintext
	signed := sign(sender, buf.Bytes(), padded)

	// encrypt padded plaintext with the session key, using the encrypted headers as AD
	ciphertext, err := demEncrypt(session, signed, buf.Bytes())
	if err != nil {
		return nil, err
	}
	buf.Write(ciphertext)

	// return KEM encrypted headers + DEM encrypted padded plaintext
	return buf.Bytes(), nil
}

// Decrypt returns the plaintext of the given Veil ciphertext iff it is decryptable by the given
// private/public key pair and it has not been altered in any way. If the ciphertext was not
// encrypted with the given key pair or if the ciphertext was altered, an error is returned.
func Decrypt(recipient ed25519.PrivateKey, sender ed25519.PublicKey, ciphertext []byte) ([]byte, error) {
	r := bytes.NewReader(ciphertext)

	// look for decryptable header
	encryptedHeader := make([]byte, encryptedHeaderLen)
	dek := make([]byte, demKeyLen)
	var offset, size uint64
	for {
		// read a header's worth of data
		_, err := io.ReadFull(r, encryptedHeader)
		if err == io.EOF {
			return nil, errors.New("invalid ciphertext")
		} else if err != nil {
			return nil, err
		}

		// try to decrypt it
		header, err := kemDecrypt(recipient, encryptedHeader)
		if err == nil {
			// if we can decrypt it, read the data encapsulation key, offset, size, and digest
			r := bytes.NewReader(header)
			_, _ = io.ReadFull(r, dek)
			_ = binary.Read(r, binary.BigEndian, &offset)
			_ = binary.Read(r, binary.BigEndian, &size)
			break
		}
	}

	// decrypt signed, padded plaintext
	signed, err := demDecrypt(dek, ciphertext[offset:], ciphertext[:offset])
	if err != nil {
		return nil, err
	}

	// verify signature
	padded := verify(sender, ciphertext[:offset], signed)
	if padded == nil {
		return nil, errors.New("invalid ciphertext")
	}

	// strip padding
	return padded[:size], nil
}

func sign(private ed25519.PrivateKey, headers, padded []byte) []byte {
	input := make([]byte, len(headers)+len(padded))
	copy(input, headers)
	copy(input[len(headers):], padded)
	sig := ed25519.Sign(private, input)

	output := make([]byte, len(padded)+sigLen)
	copy(output, sig)
	copy(output[sigLen:], padded)
	return output
}

func verify(public ed25519.PublicKey, headers, padded []byte) []byte {
	sig := padded[:sigLen]
	plaintext := padded[sigLen:]

	input := make([]byte, len(headers)+len(plaintext))
	copy(input, headers)
	copy(input[len(headers):], plaintext)

	if ed25519.Verify(public, input, sig) {
		return plaintext
	}
	return nil
}

func encodeHeader(session []byte, recipients int, plaintext []byte) []byte {
	header := bytes.NewBuffer(nil)
	header.Write(session)
	_ = binary.Write(header, binary.BigEndian, uint64(encryptedHeaderLen*recipients))
	_ = binary.Write(header, binary.BigEndian, uint64(len(plaintext)))
	return header.Bytes()
}

func addFakes(recipients []ed25519.PublicKey, fakes int) ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, len(recipients)+fakes)
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

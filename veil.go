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

	"golang.org/x/crypto/ed25519"
)

const (
	headerLen          = demKeyLen + 8 + 8
	encryptedHeaderLen = headerLen + kemOverhead
	sigLen             = 64
)

// Encrypt returns a Veil ciphertext containing the given plaintext, decryptable by the given
// recipients, with the given number of random padding bytes and fake recipients.
func Encrypt(sender ed25519.PrivateKey, recipients []ed25519.PublicKey, plaintext []byte, padding, fakes int) ([]byte, error) {
	// Add fake recipients.
	recipients, err := addFakes(recipients, fakes)
	if err != nil {
		return nil, err
	}

	// Generate a random data encapsulation key.
	dek := make([]byte, demKeyLen)
	_, err = io.ReadFull(rand.Reader, dek)
	if err != nil {
		return nil, err
	}

	// Encode the data encapsulation key, offset, and size into a header.
	header := encodeHeader(dek, len(recipients), plaintext)

	// Write KEM-encrypted copies of the header.
	buf := bytes.NewBuffer(nil)
	fake := make([]byte, headerLen+kemOverhead)
	for _, public := range recipients {
		if public == nil {
			// To fake a recipient, write a header-sized block of random data.
			_, err = io.ReadFull(rand.Reader, fake)
			if err != nil {
				return nil, err
			}
			buf.Write(fake)
		} else {
			// To include a real recipient, encrypt the header via KEM.
			b, err := kemEncrypt(public, header)
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
	}

	// Pad the plaintext with random data.
	padded := make([]byte, len(plaintext)+padding)
	copy(padded[:len(plaintext)], plaintext)
	_, err = io.ReadFull(rand.Reader, padded[len(plaintext):])
	if err != nil {
		return nil, err
	}

	// Generate an Ed25519 signature of the encrypted headers and the padded plaintext and prepend
	// it to the padded plaintext.
	signed := sign(sender, buf.Bytes(), padded)

	// Encrypt the signed, padded plaintext with the data encapsulation key, using the encrypted
	// headers as authenticated data.
	ciphertext, err := demEncrypt(dek, signed, buf.Bytes())
	if err != nil {
		return nil, err
	}
	buf.Write(ciphertext)

	// Return the KEM-encrypted headers and the DEM-encrypted, signed, padded plaintext.
	return buf.Bytes(), nil
}

// Decrypt returns the plaintext of the given Veil ciphertext iff it is decryptable by the given
// private/public key pair and it has not been altered in any way. If the ciphertext was not
// encrypted with the given key pair or if the ciphertext was altered, an error is returned.
func Decrypt(recipient ed25519.PrivateKey, sender ed25519.PublicKey, ciphertext []byte) ([]byte, error) {
	r := bytes.NewReader(ciphertext)

	// Scan through the ciphertext, one header-sized block at a time.
	encryptedHeader := make([]byte, encryptedHeaderLen)
	dek := make([]byte, demKeyLen)
	var offset, size uint64
	for {
		// Read an encrypted header's worth of data.
		_, err := io.ReadFull(r, encryptedHeader)
		if err == io.ErrUnexpectedEOF {
			// If we reach the end of the ciphertext, we cannot decrypt it.
			return nil, errors.New("invalid ciphertext")
		} else if err != nil {
			return nil, err
		}

		// Try to encrypt the possible header.
		header, err := kemDecrypt(recipient, encryptedHeader)
		if err == nil {
			// If we can decrypt it, read the data encapsulation key, offset, and size.
			r := bytes.NewReader(header)
			_, _ = io.ReadFull(r, dek)
			_ = binary.Read(r, binary.BigEndian, &offset)
			_ = binary.Read(r, binary.BigEndian, &size)
			break
		}
	}

	// Decrypt the DEM-encrypted, signed, padded plaintext.
	signed, err := demDecrypt(dek, ciphertext[offset:], ciphertext[:offset])
	if err != nil {
		return nil, err
	}

	// Remove and verify the Ed25519 signature.
	padded := verify(sender, ciphertext[:offset], signed)
	if padded == nil {
		return nil, errors.New("invalid ciphertext")
	}

	// Strip the random padding and return the original plaintext.
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

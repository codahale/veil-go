// Package veil provides an implementation of the Veil hybrid cryptosystem.
//
// Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
// authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
// Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
// encrypted. As a result, a global passive adversary would be unable to gain any information from a
// Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
// true length, and fake recipients can be added to disguise their true number from other
// recipients.
//
// You should not use this.
package veil

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// PublicKey consists of the Elligator2 representation of an X25519 public key for encrypting and an
// Ed25519 public key for verifying.
type PublicKey struct {
	// EncryptingKey is an Elligator2 representation of an X25519 public key.
	EncryptingKey []byte
	// VerifyingKey is an Ed25519 public key.
	VerifyingKey []byte
}

// PrivateKey consists of an X25519 private key for decrypting and an Ed25519 private key for
// signing.
type PrivateKey struct {
	// DecryptingKey is an X25519 private key.
	DecryptingKey []byte
	// SigningKey is an Ed25519 private key.
	SigningKey []byte
}

// GenerateKeys generates a new pair of X25519 and Ed25519 keys.
func GenerateKeys(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	// Generate a Ed25519 key pair.
	verifyingKey, signingKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random X25519 secret key.
	var xPrivate, xPublic [32]byte
	_, err = io.ReadFull(rand, xPrivate[:])
	if err != nil {
		return nil, nil, err
	}

	// Calculate the X25519 public key.
	curve25519.ScalarBaseMult(&xPublic, &xPrivate)

	return &PublicKey{EncryptingKey: xPublic[:], VerifyingKey: verifyingKey},
		&PrivateKey{DecryptingKey: xPrivate[:], SigningKey: signingKey},
		nil
}

const (
	headerLen          = demKeyLen + 8 + 8
	encryptedHeaderLen = headerLen + kemOverhead
	sigLen             = 64
)

// Encrypt returns a Veil ciphertext containing the given plaintext, decryptable by the given
// recipients, with the given number of random padding bytes and fake recipients.
func Encrypt(rand io.Reader, sender *PrivateKey, recipients []*PublicKey, plaintext []byte, padding, fakes int) ([]byte, error) {
	// Add fake recipients.
	recipients, err := addFakes(rand, recipients, fakes)
	if err != nil {
		return nil, err
	}

	// Generate a random data encapsulation key.
	dek := make([]byte, demKeyLen)
	_, err = io.ReadFull(rand, dek)
	if err != nil {
		return nil, err
	}

	// Encode the data encapsulation key, offset, and size into a header.
	header := make([]byte, headerLen)
	copy(header, dek)
	offset := encryptedHeaderLen * len(recipients)
	binary.BigEndian.PutUint64(header[demKeyLen:], uint64(offset))
	binary.BigEndian.PutUint64(header[demKeyLen+8:], uint64(len(plaintext)))

	// Write KEM-encrypted copies of the header.
	out := make([]byte, offset+len(plaintext)+demOverhead+sigLen+padding)
	for i, public := range recipients {
		o := i * encryptedHeaderLen
		if public == nil {
			// To fake a recipient, write a header-sized block of random data.
			_, err = io.ReadFull(rand, out[o:(o+encryptedHeaderLen)])
			if err != nil {
				return nil, err
			}
		} else {
			// To include a real recipient, encrypt the header via KEM.
			b, err := kemEncrypt(rand, public.EncryptingKey, header)
			if err != nil {
				return nil, err
			}
			copy(out[o:], b)
		}
	}

	// Pad the plaintext with random data.
	padded := make([]byte, len(plaintext)+padding)
	copy(padded[:len(plaintext)], plaintext)
	_, err = io.ReadFull(rand, padded[len(plaintext):])
	if err != nil {
		return nil, err
	}

	// Generate an Ed25519 signature of the encrypted headers and the padded plaintext and prepend
	// it to the padded plaintext.
	signature := ed25519.Sign(sender.SigningKey, signatureInput(out[:offset], padded))
	signed := append(signature, padded...)

	// Encrypt the signed, padded plaintext with the data encapsulation key, using the encrypted
	// headers as authenticated data.
	ciphertext, err := demEncrypt(rand, dek, signed, out[:offset])
	if err != nil {
		return nil, err
	}
	copy(out[offset:], ciphertext)

	// Return the KEM-encrypted headers and the DEM-encrypted, signed, padded plaintext.
	return out, nil
}

// Decrypt returns the plaintext of the given Veil ciphertext iff it is decryptable by the given
// private key, signed by the given public key pair it has not been altered in any way. If the
// ciphertext was not encrypted with the given key pair or if the ciphertext was altered, an error
// is returned.
func Decrypt(recipient *PrivateKey, sender *PublicKey, ciphertext []byte) ([]byte, error) {
	var dek []byte
	var offset, size uint64

	// Scan through the ciphertext, one header-sized block at a time.
	for i := 0; i < len(ciphertext)-encryptedHeaderLen; i += encryptedHeaderLen {
		// Try to encrypt the possible header.
		header, err := kemDecrypt(recipient.DecryptingKey, ciphertext[i:(i+encryptedHeaderLen)])
		if err == nil {
			// If we can decrypt it, read the data encapsulation key, offset, and size.
			dek = header[:demKeyLen]
			offset = binary.BigEndian.Uint64(header[demKeyLen:])
			size = binary.BigEndian.Uint64(header[demKeyLen+8:])
			break
		}
	}

	// If we reach the end of the ciphertext without finding our header, we cannot decrypt it.
	if dek == nil {
		return nil, errors.New("invalid ciphertext")
	}

	// Decrypt the DEM-encrypted, signed, padded plaintext.
	signed, err := demDecrypt(dek, ciphertext[offset:], ciphertext[:offset])
	if err != nil {
		return nil, err
	}

	// Remove and verify the Ed25519 signature.
	sig, padded := signed[:sigLen], signed[sigLen:]
	if !ed25519.Verify(sender.VerifyingKey, signatureInput(ciphertext[:offset], padded), sig) {
		return nil, errors.New("invalid ciphertext")
	}

	// Strip the random padding and return the original plaintext.
	return padded[:size], nil
}

// signatureInput returns the Ed25519 signature input given a set of encrypted headers and a padded
// plaintext.
func signatureInput(headers []byte, padded []byte) []byte {
	input := make([]byte, len(headers)+8+len(padded)+8)

	// Write the headers and their length.
	copy(input, headers)
	binary.BigEndian.PutUint64(input[len(headers):], uint64(len(headers)))

	// Write the padded plaintext and its length.
	copy(input[len(headers)+8:], padded)
	binary.BigEndian.PutUint64(input[len(input)-8:], uint64(len(padded)))
	return input
}

// addFakes returns a copy of the given slice of recipients with the given number of nils inserted
// randomly.
func addFakes(r io.Reader, recipients []*PublicKey, n int) ([]*PublicKey, error) {
	// Make a copy of the recipients with N nils at the end.
	out := make([]*PublicKey, len(recipients)+n)
	copy(out, recipients)

	// Perform a Fisher-Yates shuffle, using crypto/rand to pick indexes. This will randomly
	// distribute the N fake recipients throughout the slice.
	for i := len(out) - 1; i > 0; i-- {
		// Randomly pick a card from the unshuffled deck.
		b, err := rand.Int(r, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		j := int(b.Int64())

		// Swap it with the current card.
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

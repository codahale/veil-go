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
)

// PublicKey is an X25519 public key.
type PublicKey []byte

// SecretKey is an X25519 secret key.
type SecretKey []byte

// GenerateKeys generates a X25519 public and secret key pair.
func GenerateKeys(rand io.Reader) (PublicKey, SecretKey, error) {
	pk, _, sk, err := ephemeralKeys(rand)
	return pk, sk, err
}

const (
	headerLen          = kemKeyLen + 8 + 8
	encryptedHeaderLen = headerLen + kemOverhead
)

// Encrypt encrypts the given plaintext using the given secret key and list of public keys.
func Encrypt(rand io.Reader, skI SecretKey, pkI PublicKey, pkRs []PublicKey, plaintext []byte, padding, fakes int) ([]byte, error) {
	// Generate an ephemeral X25519 key pair.
	pkE, _, skE, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	// Add fake recipients.
	pkRs, err = addFakes(rand, pkRs, fakes)
	if err != nil {
		return nil, err
	}

	// Encode the ephemeral secret key, offset, and size into a header.
	header := make([]byte, headerLen)
	copy(header, skE)
	offset := encryptedHeaderLen * len(pkRs)
	binary.BigEndian.PutUint64(header[kemKeyLen:], uint64(offset))
	binary.BigEndian.PutUint64(header[kemKeyLen+8:], uint64(len(plaintext)))

	// Write KEM-encrypted copies of the header.
	out := make([]byte, offset+len(plaintext)+kemOverhead+padding)
	for i, pkR := range pkRs {
		o := i * encryptedHeaderLen
		if pkR == nil {
			// To fake a recipient, write a header-sized block of random data.
			_, err = io.ReadFull(rand, out[o:(o+encryptedHeaderLen)])
			if err != nil {
				return nil, err
			}
		} else {
			// To include a real recipient, encrypt the header via KEM.
			b, err := kemEncrypt(rand, skI, pkI, pkR, header, nil)
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

	// Encrypt the signed, padded plaintext with the ephemeral public key, using the encrypted
	// headers as authenticated data.
	ciphertext, err := kemEncrypt(rand, skI, pkI, pkE, padded, out[:offset])
	if err != nil {
		return nil, err
	}
	copy(out[offset:], ciphertext)

	// Return the encrypted headers and the encrypted, padded plaintext.
	return out, nil
}

// Decrypt uses the recipient's secret key and public key to decrypt the given message, returning
// the initiator's public key and the original plaintext. If any bit of the ciphertext has been
// altered, or if the message was not encrypted for the given secret key, or if the initiator's
// public key was not provided, returns an error.
func Decrypt(skR SecretKey, pkR PublicKey, pkIs []PublicKey, ciphertext []byte) (PublicKey, []byte, error) {
	var skE, pkI []byte
	var offset, size uint64

	// Scan through the ciphertext, one header-sized block at a time.
	for _, pk := range pkIs {
		for i := 0; i < len(ciphertext)-encryptedHeaderLen; i += encryptedHeaderLen {
			// Try to decrypt the possible header.
			b := ciphertext[i:(i + encryptedHeaderLen)]
			header, err := kemDecrypt(skR, pkR, pk, b, nil)
			if err == nil {
				// If we can decrypt it, read the ephemeral secret key, offset, and size.
				pkI = pk
				skE = header[:kemKeyLen]
				offset = binary.BigEndian.Uint64(header[kemKeyLen:])
				size = binary.BigEndian.Uint64(header[kemKeyLen+8:])
				break
			}
		}
	}

	// If we reach the end of the ciphertext without finding our header, we cannot decrypt it.
	if skE == nil {
		return nil, nil, errors.New("invalid ciphertext")
	}

	// Re-derive the ephemeral X25519 public key.
	var buf, pkE [32]byte
	copy(buf[:], skE)
	curve25519.ScalarBaseMult(&pkE, &buf)

	// Decrypt the KEM-encrypted, padded plaintext.
	padded, err := kemDecrypt(skE, pkE[:], pkI, ciphertext[offset:], ciphertext[:offset])
	if err != nil {
		return nil, nil, err
	}

	// Strip the random padding and return the initiator's public key and the original plaintext.
	return pkI, padded[:size], nil
}

// addFakes returns a copy of the given slice of recipients with the given number of nils inserted
// randomly.
func addFakes(r io.Reader, keys []PublicKey, n int) ([]PublicKey, error) {
	// Make a copy of the recipients with N nils at the end.
	out := make([]PublicKey, len(keys)+n)
	copy(out, keys)

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

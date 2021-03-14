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

	"github.com/bwesterb/go-ristretto"
)

// PublicKey is an Ristretto255/DH public key.
type PublicKey []byte

func (pk PublicKey) toPoint() (*ristretto.Point, error) {
	var q ristretto.Point

	if err := q.UnmarshalBinary(pk); err != nil {
		return nil, err
	}

	return &q, nil
}

// SecretKey is an Ristretto255/DH secret key.
type SecretKey []byte

func (sk SecretKey) toScalar() (*ristretto.Scalar, error) {
	var s ristretto.Scalar

	if err := s.UnmarshalBinary(sk); err != nil {
		return nil, err
	}

	return &s, nil
}

// KeyPair is an Ristretto255/DH secret key and its matching public key.
type KeyPair struct {
	// PublicKey is the public key of the pair and should be transmitted publicly.
	PublicKey PublicKey
	// SecretKey is the secret key of the pair and should be stored securely.
	SecretKey SecretKey
}

// ErrInvalidCiphertext is returned when a ciphertext cannot be decrypted, either due to an
// incorrect key or tampering.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

// NewKeyPair create a new Ristretto255/DH public and secret key pair.
func NewKeyPair(rand io.Reader) (*KeyPair, error) {
	pk, _, sk, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	return &KeyPair{PublicKey: pk.Bytes(), SecretKey: sk.Bytes()}, nil
}

const (
	headerLen          = kemKeyLen + 8 + 8
	encryptedHeaderLen = headerLen + kemOverhead
)

// Encrypt encrypts the given plaintext for list of public keys.
func (kp *KeyPair) Encrypt(
	rand io.Reader, publicKeys []PublicKey, plaintext []byte, padding, fakes int,
) ([]byte, error) {
	// Generate an ephemeral Ristretto255/DH key pair.
	pkE, _, skE, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	// Add fake recipients.
	publicKeys, err = addFakes(rand, publicKeys, fakes)
	if err != nil {
		return nil, err
	}

	// Encode the ephemeral secret key, offset, and size into a header.
	header := make([]byte, headerLen)
	copy(header, skE.Bytes())

	offset := encryptedHeaderLen * len(publicKeys)
	binary.BigEndian.PutUint64(header[kemKeyLen:], uint64(offset))
	binary.BigEndian.PutUint64(header[kemKeyLen+8:], uint64(len(plaintext)))

	// Allocate room for encrypted copies of the header.
	out := make([]byte, offset+len(plaintext)+kemOverhead+padding)

	// Decode the public key.
	pk, err := kp.PublicKey.toPoint()
	if err != nil {
		return nil, err
	}

	// Decode the secret key.
	sk, err := kp.SecretKey.toScalar()
	if err != nil {
		return nil, err
	}

	// Write KEM-encrypted copies of the header.
	if err := writeHeaders(pk, sk, rand, publicKeys, header, out); err != nil {
		return nil, err
	}

	// Copy the plaintext into a buffer with room for padding.
	padded := make([]byte, len(plaintext)+padding)
	copy(padded[:len(plaintext)], plaintext)

	// Pad the plaintext with random data.
	if _, err := io.ReadFull(rand, padded[len(plaintext):]); err != nil {
		return nil, err
	}

	// Encrypt the signed, padded plaintext with the ephemeral public key, using the encrypted
	// headers as authenticated data.
	ciphertext, err := kemEncrypt(rand, pk, sk, pkE, padded, out[:offset])
	if err != nil {
		return nil, err
	}

	copy(out[offset:], ciphertext)

	// Return the encrypted headers and the encrypted, padded plaintext.
	return out, nil
}

func writeHeaders(
	pk *ristretto.Point, sk *ristretto.Scalar, rand io.Reader, publicKeys []PublicKey, header, dst []byte,
) error {
	for i, pkB := range publicKeys {
		o := i * encryptedHeaderLen
		if pkB == nil {
			// To fake a recipient, write a header-sized block of random data.
			if _, err := io.ReadFull(rand, dst[o:(o+encryptedHeaderLen)]); err != nil {
				return err
			}
		} else {
			// To include a real recipient, encrypt the header via KEM.
			b, err := writeHeader(pk, sk, rand, pkB, header)
			if err != nil {
				return err
			}

			copy(dst[o:], b)
		}
	}

	return nil
}

func writeHeader(
	pk *ristretto.Point, sk *ristretto.Scalar, rand io.Reader, pkB PublicKey, header []byte,
) ([]byte, error) {
	// Decode the recipient's public key.
	pkR, err := pkB.toPoint()
	if err != nil {
		return nil, err
	}

	// Write an encrypted copy of the header via KEM.
	b, err := kemEncrypt(rand, pk, sk, pkR, header, nil)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Decrypt uses the recipient's secret key and public key to decrypt the given message, returning
// the initiator's public key and the original plaintext. If any bit of the ciphertext has been
// altered, or if the message was not encrypted for the given secret key, or if the initiator's
// public key was not provided, returns an error.
func (kp *KeyPair) Decrypt(publicKeys []PublicKey, ciphertext []byte) (PublicKey, []byte, error) {
	// Decode the public key.
	pk, err := kp.PublicKey.toPoint()
	if err != nil {
		return nil, nil, err
	}

	// Decode the secret key.
	sk, err := kp.SecretKey.toScalar()
	if err != nil {
		return nil, nil, err
	}

	pkI, skE, offset, size, err := decryptHeader(publicKeys, ciphertext, pk, sk)
	if err != nil {
		return nil, nil, err
	}

	// If we reach the end of the ciphertext without finding our header, we cannot decrypt it.
	if pkI == nil {
		return nil, nil, ErrInvalidCiphertext
	}

	// Re-derive the ephemeral Ristretto255/DH public key.
	pkE := sk2pk(skE)

	// Decrypt the KEM-encrypted, padded plaintext.
	padded, err := kemDecrypt(pkE, skE, pkI, ciphertext[offset:], ciphertext[:offset])
	if err != nil {
		return nil, nil, err
	}

	// Strip the random padding and return the initiator's public key and the original plaintext.
	return pkI.Bytes(), padded[:size], nil
}

func decryptHeader(
	publicKeys []PublicKey, ciphertext []byte, pk *ristretto.Point, sk *ristretto.Scalar,
) (*ristretto.Point, *ristretto.Scalar, uint64, uint64, error) {
	// Scan through the ciphertext, one header-sized block at a time.
	for _, pkB := range publicKeys {
		// Decode the possible sender's public key.
		pkR, err := pkB.toPoint()
		if err != nil {
			return nil, nil, 0, 0, err
		}

		for i := 0; i < len(ciphertext)-encryptedHeaderLen; i += encryptedHeaderLen {
			b := ciphertext[i:(i + encryptedHeaderLen)]

			// Try to decrypt the possible header.
			header, err := kemDecrypt(pk, sk, pkR, b, nil)
			if err == nil {
				// If we can decrypt it, read the ephemeral secret key, offset, and size.
				var skE ristretto.Scalar
				_ = skE.UnmarshalBinary(header[:kemKeyLen])
				offset := binary.BigEndian.Uint64(header[kemKeyLen:])
				size := binary.BigEndian.Uint64(header[kemKeyLen+8:])

				// Proceed with the decrypted ephemeral key.
				return pkR, &skE, offset, size, nil
			}
		}
	}

	// If no header was decrypted, return failure.
	return nil, nil, 0, 0, nil
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

		// Convert to a platform int.
		j := int(b.Int64())

		// Swap it with the current card.
		out[i], out[j] = out[j], out[i]
	}

	return out, nil
}

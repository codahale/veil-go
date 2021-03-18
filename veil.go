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
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/bwesterb/go-ristretto"
)

// PublicKey is an Ristretto255/DH public key.
type PublicKey struct {
	rk []byte
	q  ristretto.Point
}

// Equals returns true if the given PublicKey is equal to the receiver.
func (pk *PublicKey) Equals(other *PublicKey) bool {
	return pk.q.Equals(&other.q)
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.rk, nil
}

func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	pk.rk = data
	pk.q = rk2pk(data)

	return nil
}

func (pk *PublicKey) MarshalText() ([]byte, error) {
	b, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	t := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(t, b)

	return t, nil
}

func (pk *PublicKey) UnmarshalText(text []byte) error {
	b, err := base64.RawURLEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return pk.UnmarshalBinary(b)
}

func (pk *PublicKey) String() string {
	s, _ := pk.MarshalText()
	return string(s)
}

var (
	_ encoding.BinaryMarshaler   = &PublicKey{}
	_ encoding.BinaryUnmarshaler = &PublicKey{}
	_ encoding.TextMarshaler     = &PublicKey{}
	_ encoding.TextUnmarshaler   = &PublicKey{}
	_ fmt.Stringer               = &PublicKey{}
)

// SecretKey is an Ristretto255/DH secret key.
type SecretKey struct {
	pk PublicKey
	s  ristretto.Scalar
}

func (sk *SecretKey) String() string {
	return sk.pk.String()
}

// PublicKey returns the public key for the given secret key.
func (sk *SecretKey) PublicKey() *PublicKey {
	return &sk.pk
}

var _ fmt.Stringer = &SecretKey{}

// NewSecretKey creates a new Ristretto255/DH secret key.
func NewSecretKey(rand io.Reader) (*SecretKey, error) {
	// Always generate a key with a possible Elligator2 representative.
	q, rk, s, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	return &SecretKey{s: s, pk: PublicKey{q: q, rk: rk}}, nil
}

// ErrInvalidCiphertext is returned when a ciphertext cannot be decrypted, either due to an
// incorrect key or tampering.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

const (
	headerLen          = kemPublicKeyLen + 8 + 8
	encryptedHeaderLen = headerLen + kemOverhead
)

// Encrypt encrypts the given plaintext for list of public keys.
func (sk *SecretKey) Encrypt(
	rand io.Reader, publicKeys []*PublicKey, plaintext []byte, padding, fakes int,
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
	offset := encryptedHeaderLen * len(publicKeys)
	size := len(plaintext)
	header := encodeHeader(&skE, offset, size)

	// Encrypt copies of the header for each recipient.
	headers, err := encryptHeaders(rand, header, &sk.s, &sk.pk.q, publicKeys)
	if err != nil {
		return nil, err
	}

	// Write KEM-encrypted copies of the header.
	buf := bytes.NewBuffer(make([]byte, 0, offset+size+kemOverhead+padding))
	_, _ = buf.Write(headers)

	// Copy the plaintext into a buffer with room for padding.
	padded := bytes.NewBuffer(make([]byte, 0, size+padding))
	_, _ = padded.Write(plaintext)

	// Pad the plaintext with random data.
	if _, err := io.CopyN(padded, rand, int64(padding)); err != nil {
		return nil, err
	}

	// Encrypt the signed, padded plaintext with the ephemeral public key, using the encrypted
	// headers as authenticated data.
	ciphertext, err := kemEncrypt(rand, &sk.s, &sk.pk.q, &pkE, padded.Bytes(), headers)
	if err != nil {
		return nil, err
	}

	// Write the ciphertext.
	_, _ = buf.Write(ciphertext)

	// Return the encrypted headers and the encrypted, padded plaintext.
	return buf.Bytes(), nil
}

// encodeHeader returns a header with the ephemeral secret key, the ciphertext offset, and the
// ciphertext length.
func encodeHeader(skE *ristretto.Scalar, offset, size int) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, headerLen))
	_, _ = buf.Write(skE.Bytes())
	_ = binary.Write(buf, binary.BigEndian, uint64(offset))
	_ = binary.Write(buf, binary.BigEndian, uint64(size))

	return buf.Bytes()
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func encryptHeaders(
	rand io.Reader, header []byte, skI *ristretto.Scalar, pkI *ristretto.Point, publicKeys []*PublicKey,
) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(header)*len(publicKeys)))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		if pkR == nil {
			// To fake a recipient, write a header-sized block of random data.
			if _, err := io.CopyN(buf, rand, encryptedHeaderLen); err != nil {
				return nil, err
			}
		} else {
			// To include a real recipient, encrypt the header via KEM.
			b, err := kemEncrypt(rand, skI, pkI, &pkR.q, header, nil)
			if err != nil {
				return nil, err
			}

			_, _ = buf.Write(b)
		}
	}

	return buf.Bytes(), nil
}

// Decrypt uses the recipient's secret key and public key to decrypt the given message, returning
// the initiator's public key and the original plaintext. If any bit of the ciphertext has been
// altered, or if the message was not encrypted for the given secret key, or if the initiator's
// public key was not provided, returns an error.
func (sk SecretKey) Decrypt(publicKeys []*PublicKey, ciphertext []byte) (*PublicKey, []byte, error) {
	var (
		pkI          *PublicKey
		skE          ristretto.Scalar
		offset, size uint64
	)

	// Scan through the ciphertext, one header-sized block at a time.
	for _, pkR := range publicKeys {
		for i := 0; i < len(ciphertext)-encryptedHeaderLen; i += encryptedHeaderLen {
			b := ciphertext[i:(i + encryptedHeaderLen)]

			// Try to decrypt the possible header.
			header, err := kemDecrypt(&pkR.q, &sk.pk.q, &sk.s, b, nil)
			if err == nil {
				// If we can decrypt it, read the ephemeral secret key, offset, and size.
				pkI = pkR
				_ = skE.UnmarshalBinary(header[:kemPublicKeyLen])
				offset = binary.BigEndian.Uint64(header[kemPublicKeyLen:])
				size = binary.BigEndian.Uint64(header[kemPublicKeyLen+8:])

				// Proceed with the decrypted ephemeral key.
				break
			}
		}
	}

	// If we reach the end of the ciphertext without finding our header, we cannot decrypt it.
	if pkI == nil {
		return nil, nil, ErrInvalidCiphertext
	}

	// Re-derive the ephemeral Ristretto255/DH public key.
	pkE := sk2pk(&skE)

	// Decrypt the KEM-encrypted, padded plaintext.
	padded, err := kemDecrypt(&pkI.q, &pkE, &skE, ciphertext[offset:], ciphertext[:offset])
	if err != nil {
		return nil, nil, err
	}

	// Strip the random padding and return the initiator's public key and the original plaintext.
	return pkI, padded[:size], nil
}

// addFakes returns a copy of the given slice of recipients with the given number of nils inserted
// randomly.
func addFakes(r io.Reader, keys []*PublicKey, n int) ([]*PublicKey, error) {
	// Make a copy of the recipients with N nils at the end.
	out := make([]*PublicKey, len(keys)+n)
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

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

	"github.com/bwesterb/go-ristretto"
)

// PublicKey is a ristretto255/XDH public key.
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
	rk2pk(&pk.q, data)

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

// SecretKey is a ristretto255/XDH secret key.
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

// NewSecretKey creates a new secret key.
func NewSecretKey() (*SecretKey, error) {
	q, rk, s, err := generateKeys()
	if err != nil {
		return nil, err
	}

	return &SecretKey{s: s, pk: PublicKey{q: q, rk: rk}}, nil
}

// ErrInvalidCiphertext is returned when a ciphertext cannot be decrypted, either due to an
// incorrect key or tampering.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

const (
	blockSize           = 1024 * 1024    // 1MiB
	headerSize          = kemRepSize + 4 // 4 bytes for message offset
	encryptedHeaderSize = headerSize + kemOverhead
)

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes written and the first
// error reported while encrypting, if any.
func (sk *SecretKey) Encrypt(dst io.Writer, src io.Reader, recipients []*PublicKey, padding int) (int64, error) {
	// Generate an ephemeral key pair.
	pkE, _, skE, err := generateKeys()
	if err != nil {
		return 0, err
	}

	// Encode the ephemeral secret key and offset into a header.
	offset := encryptedHeaderSize*len(recipients) + padding
	header := make([]byte, headerSize)
	copy(header, skE.Bytes())
	binary.BigEndian.PutUint32(header[kemRepSize:], uint32(offset))

	// Encrypt copies of the header for each recipient.
	headers, err := sk.encryptHeaders(header, recipients, padding)
	if err != nil {
		return 0, err
	}

	// Write the encrypted headers.
	n, err := dst.Write(headers)
	if err != nil {
		return int64(n), err
	}

	// Generate a shared key between the sender and the ephemeral key.
	rkW, key, _, err := kemSend(&sk.s, &sk.pk.q, &pkE, false)
	if err != nil {
		return int64(n), err
	}

	// Write the wrapper Elligator2 representative.
	an, err := dst.Write(rkW)
	if err != nil {
		return int64(n + an), err
	}

	// Initialize an AEAD writer with the key and nonce, using the encrypted headers as
	// authenticated data.
	w := newAEADWriter(dst, key, headers, blockSize)

	// Encrypt the plaintext as a stream.
	bn, err := io.Copy(w, src)
	if err != nil {
		return bn + int64(n+an), err
	}

	// Return the bytes written and flush any buffers.
	return bn + int64(n+an), w.Close()
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func (sk *SecretKey) encryptHeaders(header []byte, publicKeys []*PublicKey, padding int) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(header)*len(publicKeys)))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		// Generate KEM keys for the recipient.
		rkE, key, nonce, err := kemSend(&sk.s, &sk.pk.q, &pkR.q, true)
		if err != nil {
			return nil, err
		}

		// Use the key with AES-256-GCM+HMAC-SHA2-512/256.
		aead := newHMACAEAD(key)

		// Encrypt the header for the recipient.
		b := aead.Seal(nil, nonce, header, nil)

		// Write the ephemeral representative and the ciphertext.
		_, _ = buf.Write(rkE)
		_, _ = buf.Write(b)
	}

	// Add padding if any is required.
	if padding > 0 {
		if _, err := io.CopyN(buf, rand.Reader, int64(padding)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts the data in src if originally encrypted by any of the given public keys. Returns
// the sender's public key, the number of decrypted bytes written, and the first reported error, if
// any.
// N.B.: Because Veil messages are streamed, it is possible that this may write some decrypted data
// to dst before it can discover that the ciphertext is invalid. If Decrypt returns an error, all
// output written to dst should be discarded, as it cannot be ascertained to be authentic.
func (sk *SecretKey) Decrypt(dst io.Writer, src io.Reader, senders []*PublicKey) (*PublicKey, int64, error) {
	var pkE ristretto.Point

	// Find a decryptable header and recover the ephemeral secret key.
	headers, pkS, skE, err := sk.findHeader(src, senders)
	if err != nil {
		return nil, 0, err
	}

	// Re-derive the ephemeral public key.
	sk2pk(&pkE, skE)

	// Read the ephemeral representative.
	rkW := make([]byte, kemRepSize)
	if _, err := io.ReadFull(src, rkW); err != nil {
		return nil, 0, err
	}

	// Derive the shared key between the sender and the ephemeral key.
	key, _ := kemReceive(skE, &pkE, &pkS.q, rkW, false)

	// Initialize an AEAD reader with the key and nonce, using the encrypted headers as
	// authenticated data.
	r := newAEADReader(src, key, headers, blockSize)

	// Decrypt the plaintext as a stream.
	n, err := io.Copy(dst, r)
	if err != nil {
		return nil, n, err
	}

	// Return the sender's public key and the number of bytes written.
	return pkS, n, nil
}

// findHeader scans src for header blocks encrypted by any of the given possible senders. Returns
// the full slice of encrypted headers, the sender's public key, and the ephemeral secret key.
func (sk *SecretKey) findHeader(src io.Reader, senders []*PublicKey) ([]byte, *PublicKey, *ristretto.Scalar, error) {
	headers := make([]byte, 0, len(senders)*encryptedHeaderSize) // a guess at initial capacity
	buf := make([]byte, encryptedHeaderSize)

	for {
		// Iterate through src in header-sized blocks.
		_, err := io.ReadFull(src, buf)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// If we hit an EOF, expected and/or otherwise, this is the final block. We didn't find
			// a header we could decrypt, so the ciphertext is invalid.
			return nil, nil, nil, ErrInvalidCiphertext
		} else if err != nil {
			return nil, nil, nil, err
		}

		// Append the current header to the list of encrypted headers.
		headers = append(headers, buf...)

		// Copy the ephemeral public key representative.
		rkE := make([]byte, kemRepSize)
		copy(rkE, buf)

		// Copy the ciphertext.
		ciphertext := make([]byte, len(buf)-kemRepSize)
		copy(ciphertext, buf[kemRepSize:])

		// Attempt to decrypt the header.
		pkS, skE, offset := sk.decryptHeader(rkE, ciphertext, senders)
		if pkS != nil {
			// If we successfully decrypt the header, use the message offset to read the remaining
			// encrypted headers.
			remaining := make([]byte, offset-len(headers))
			if _, err := io.ReadFull(src, remaining); err != nil {
				return nil, nil, nil, err
			}

			// Return the full set of encrypted headers, the sender's public key, and the ephemeral
			// secret key.
			return append(headers, remaining...), pkS, skE, nil
		}
	}
}

// decryptHeader attempts to decrypt the given header block if sent from any of the given public
// keys.
func (sk *SecretKey) decryptHeader(rkE, ciphertext []byte, senders []*PublicKey) (*PublicKey, *ristretto.Scalar, int) {
	var skE ristretto.Scalar

	// Iterate through all possible senders.
	for _, pkS := range senders {
		// Re-derive the KEM key and nonce between the sender and recipient.
		key, nonce := kemReceive(&sk.s, &sk.pk.q, &pkS.q, rkE, true)

		// Use the key with AES-256-GCM+HMAC-SHA2-512/256.
		aead := newHMACAEAD(key)

		// Try to decrypt the header. If the header cannot be decrypted, it means the header wasn't
		// encrypted for us by this possible sender. Continue to the next possible sender.
		header, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue
		}

		// If the header wss successful decrypted, decode the ephemeral secret key and message
		// offset and return them.
		_ = skE.UnmarshalBinary(header[:kemRepSize])
		offset := binary.BigEndian.Uint32(header[kemRepSize:])

		return pkS, &skE, int(offset)
	}

	return nil, nil, 0
}

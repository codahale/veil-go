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
	crand "crypto/rand"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/chacha20poly1305"
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
	headerLen          = kemPublicKeyLen + 4
	encryptedHeaderLen = headerLen + kemOverhead
	blockSize          = 1024
)

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes written and the first
// error reported while encrypting, if any.
func (sk *SecretKey) Encrypt(dst io.Writer, src, rand io.Reader, recipients []*PublicKey) (int, error) {
	// Generate an ephemeral Ristretto255/DH key pair.
	pkE, _, skE, err := ephemeralKeys(rand)
	if err != nil {
		return 0, err
	}

	// Encode the ephemeral secret key and offset into a header.
	offset := encryptedHeaderLen * len(recipients)
	header := make([]byte, headerLen)
	copy(header, skE.Bytes())
	binary.BigEndian.PutUint32(header[kemPublicKeyLen:], uint32(offset))

	// Encrypt copies of the header for each recipient.
	headers, err := sk.encryptHeaders(rand, header, recipients)
	if err != nil {
		return 0, err
	}

	// Write the encrypted headers.
	n, err := dst.Write(headers)
	if err != nil {
		return n, err
	}

	// Generate a shared key and nonce between the sender and the ephemeral key.
	rkW, key, nonce, err := kemSend(rand, &sk.s, &sk.pk.q, &pkE, headers)
	if err != nil {
		return n, err
	}

	// Write the wrapper Elligator2 representative.
	an, err := dst.Write(rkW)
	if err != nil {
		return n + an, err
	}

	// Initialize an AEAD stream with the key and nonce.
	stream := newAEADStream(key, nonce)

	// Encrypt the plaintext as a stream.
	bn, err := stream.encrypt(dst, src, nil, blockSize)
	if err != nil {
		return n + an + bn, err
	}

	return n + an + bn, nil
}

// Decrypt decrypts the data in src if originally encrypted by any of the given public keys. Returns
// the sender's public key, the number of decrypted bytes written, and the first reported error, if
// any.
func (sk *SecretKey) Decrypt(dst io.Writer, src io.Reader, senders []*PublicKey) (*PublicKey, int, error) {
	// Find a decryptable header and recover the ephemeral secret key.
	headers, pkS, skE, err := sk.findHeader(src, senders)
	if err != nil {
		return nil, 0, err
	}

	// Re-derive the ephemeral Ristretto255/DH public key.
	pkE := sk2pk(skE)

	// Read the ephemeral Elligator2 representative.
	rkW := make([]byte, kemPublicKeyLen)
	if _, err := io.ReadFull(src, rkW); err != nil {
		return nil, 0, err
	}

	// Derive the shared key and nonce between the sender and the ephemeral key.
	key, nonce, err := kemReceive(skE, &pkE, &pkS.q, rkW, headers)
	if err != nil {
		return nil, 0, err
	}

	// Initialize an AEAD stream with the key and nonce.
	stream := newAEADStream(key, nonce)

	// Decrypt the original stream.
	n, err := stream.decrypt(dst, src, nil, blockSize)
	if err != nil {
		return nil, n, err
	}

	// Return the sender's public key and the number of bytes written.
	return pkS, n, nil
}

// findHeader scans src for header blocks encrypted by any of the given possible senders. Returns
// the full slice of encrypted headers, the sender's public key, and the ephemeral secret key.
//nolint:gocognit // This isn't actually that complicated.
func (sk *SecretKey) findHeader(src io.Reader, senders []*PublicKey) ([]byte, *PublicKey, *ristretto.Scalar, error) {
	headers := make([]byte, 0, len(senders)*encryptedHeaderLen)
	buf := make([]byte, encryptedHeaderLen)

	for {
		// Iterate through src in header-sized blocks.
		_, err := io.ReadFull(src, buf)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// If we hit the end of src without finding a decryptable header, then the ciphertext is
			// not valid for the given parameters.
			return nil, nil, nil, ErrInvalidCiphertext
		} else if err != nil {
			return nil, nil, nil, err
		}

		// Append the current header to the list of encrypted headers.
		headers = append(headers, buf...)

		// Attempt to decrypt the header.
		pkS, skE, offset, err := sk.decryptHeader(buf, senders)
		if err != nil {
			return nil, nil, nil, err
		}

		// If we successfully decrypt the header, use the message offset to read the remaining
		// encrypted headers.
		if pkS != nil {
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
func (sk *SecretKey) decryptHeader(header []byte, senders []*PublicKey) (*PublicKey, *ristretto.Scalar, int, error) {
	var skE ristretto.Scalar

	// Separate the Elligator2 representative from the ciphertext.
	rkE, ciphertext := header[:kemPublicKeyLen], header[kemPublicKeyLen:]

	// Iterate through all possible senders.
	for _, pkR := range senders {
		// Re-derive the KEM key and nonce between the sender and recipient.
		key, nonce, err := kemReceive(&sk.s, &sk.pk.q, &pkR.q, rkE, nil)
		if err != nil {
			return nil, nil, 0, err
		}

		// Use the key and nonce with ChaCha20Poly1305.
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}

		// Try to decrypt the header. If the header cannot be decrypted, it means the header wasn't
		// encrypted for us by this possible sender. Continue to the next possible sender.
		header, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue
		}

		// If the header wss successful decrypted, decode the ephemeral secret key and message
		// offset and return them.
		_ = skE.UnmarshalBinary(header[:kemPublicKeyLen])
		offset := binary.BigEndian.Uint32(header[kemPublicKeyLen:])

		return pkR, &skE, int(offset), nil
	}

	return nil, nil, 0, nil
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func (sk *SecretKey) encryptHeaders(rand io.Reader, header []byte, publicKeys []*PublicKey) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(header)*len(publicKeys)))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		// Generate KEM keys for the recipient.
		rkE, key, nonce, err := kemSend(rand, &sk.s, &sk.pk.q, &pkR.q, nil)
		if err != nil {
			return nil, err
		}

		// Use the key and nonce with ChaCha20Poly1305.
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}

		// Encrypt the header for the recipient.
		b := aead.Seal(nil, nonce, header, nil)

		// Write the ephemeral Elligator2 representative and the ciphertext.
		_, _ = buf.Write(rkE)
		_, _ = buf.Write(b)
	}

	return buf.Bytes(), nil
}

// Pad returns an io.Reader which adds n bytes of random padding to the source io.Reader.
func Pad(src, rand io.Reader, n int) io.Reader {
	// Encode the number of random bytes into a buffer.
	buf := make([]byte, 4)
	n -= len(buf)
	binary.BigEndian.PutUint32(buf, uint32(n))

	// Return a multi-reader of the number of random bytes, the random bytes, and then the source.
	return io.MultiReader(bytes.NewReader(buf), io.LimitReader(rand, int64(n)), src)
}

// Unpad removes all random padding from the given io.Reader.
func Unpad(src io.Reader) error {
	// Read the padding count.
	buf := make([]byte, 4)
	if _, err := io.ReadFull(src, buf); err != nil {
		return err
	}

	// Decode the padding count.
	padding := binary.BigEndian.Uint32(buf)

	// Discard the padding.
	if _, err := io.Copy(io.Discard, io.LimitReader(src, int64(padding))); err != nil {
		return err
	}

	return nil
}

// AddFakes adds n randomly-generated public keys to the given set of public keys, shuffles the
// results, and returns them. This allows senders of messages to conceal the true number of
// recipients of a particular message.
func AddFakes(rand io.Reader, keys []*PublicKey, n int) ([]*PublicKey, error) {
	// Make a copy of the public keys.
	out := make([]*PublicKey, len(keys), len(keys)+n)
	copy(out, keys)

	// Add n randomly generated keys to the end.
	for i := 0; i < n; i++ {
		q, rk, _, err := ephemeralKeys(rand)
		if err != nil {
			return nil, err
		}

		out = append(out, &PublicKey{
			q:  q,
			rk: rk,
		})
	}

	// Perform a Fisher-Yates shuffle, using crypto/rand to pick indexes. This will randomly
	// distribute the N fake recipients throughout the slice.
	for i := len(out) - 1; i > 0; i-- {
		// Randomly pick a card from the unshuffled deck.
		b, err := crand.Int(rand, big.NewInt(int64(i+1)))
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

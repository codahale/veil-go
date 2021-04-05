// Package r255 provides ristretto255 functionality.
//
// Veil uses ristretto255 for asymmetric cryptography. Each person has a secret key from which
// multiple private/public key pairs can be derived.
//
// To derive a private key, a secret scalar is derived from the secret key using a STROBE protocol.
// A delta scalar is derived from an opaque label using a different STROBE protocol and added to the
// secret scalar to produce a new private key.
//
// To derive a public key, the same delta scalar is derived, multiplied by the risotto255 base
// point, and added to the public key point.
//
// To sign messages, Veil creates deterministic Schnorr signatures using a STROBE protocol.
package r255

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/codahale/veil/pkg/veil/internal/protocols/rng"
	"github.com/codahale/veil/pkg/veil/internal/protocols/scaldf"
	"github.com/codahale/veil/pkg/veil/internal/protocols/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/protocols/skid"
	"github.com/gtank/ristretto255"
)

const (
	PublicKeySize  = 32                 // PublicKeySize is the length of a public key in bytes.
	PrivateKeySize = 32                 // PrivateKeySize is the length of a private key in bytes.
	SecretKeySize  = 64                 // SecretKeySize is the length of a secret key in bytes.
	SignatureSize  = PublicKeySize + 32 // SignatureSize is the length of a signature in bytes.
)

// ErrInvalidSecretKey is returned when the given data cannot be decoded as a secret key.
var ErrInvalidSecretKey = errors.New("invalid secret key")

// SecretKey is a 64-byte secret value from which private and public keys can be derived.
type SecretKey struct {
	r []byte
}

// NewSecretKey creates a new secret key.
func NewSecretKey() (*SecretKey, error) {
	// Generate a random 64-byte key.
	var r [SecretKeySize]byte
	if _, err := rng.Read(r[:]); err != nil {
		return nil, err
	}

	return DecodeSecretKey(r[:])
}

// DecodeSecretKey decodes the given bytes as a SecretKey.
func DecodeSecretKey(b []byte) (*SecretKey, error) {
	if len(b) != SecretKeySize {
		return nil, ErrInvalidSecretKey
	}

	return &SecretKey{r: b}, nil
}

// PrivateKey derives a PrivateKey instance from the receiver using the given label.
func (sk *SecretKey) PrivateKey(label string) *PrivateKey {
	// Derive the secret scalar.
	s := scaldf.Secret(sk.r)

	// Calculate the delta for the derived key.
	r := scaldf.Label([]byte(label))

	// Return the secret scalar plus the delta.
	return &PrivateKey{d: ristretto255.NewScalar().Add(s, r)}
}

// PublicKey derives a PublicKey instance from the receiver using the given label.
func (sk *SecretKey) PublicKey(label string) *PublicKey {
	return sk.PrivateKey(label).PublicKey()
}

// Encode returns the secret key as a series of bytes.
func (sk *SecretKey) Encode(b []byte) []byte {
	return append(b, sk.r...)
}

// String returns the first 8 bytes of a hash of the secret key as a hexadecimal string. This
// uniquely identifies the secret key without revealing information about it.
func (sk *SecretKey) String() string {
	return hex.EncodeToString(skid.ID(sk.r, 8))
}

var _ fmt.Stringer = &SecretKey{}

// PrivateKey is a ristretto255 scalar used to create signatures and shared secrets.
type PrivateKey struct {
	d *ristretto255.Scalar
}

// NewEphemeralKeys returns a new, random private key, unassociated with any secret key, and its
// corresponding public key.
func NewEphemeralKeys() (*PrivateKey, *PublicKey, error) {
	// Generate a random secret key.
	var r [SecretKeySize]byte
	if _, err := rng.Read(r[:]); err != nil {
		return nil, nil, err
	}

	// Create a private key scalar from the random data.
	priv := &PrivateKey{d: scaldf.Random(r[:])}

	// Return it and its public key.
	return priv, priv.PublicKey(), nil
}

// DecodePrivateKey decodes the given bytes as a private key.
func DecodePrivateKey(b []byte) (*PrivateKey, error) {
	d := ristretto255.NewScalar()
	if err := d.Decode(b); err != nil {
		return nil, err
	}

	return &PrivateKey{d: d}, nil
}

// Derive derives a PrivateKey instance from the receiver using the given label.
func (pk *PrivateKey) Derive(label string) *PrivateKey {
	// Calculate the delta for the derived key.
	r := scaldf.Label([]byte(label))

	return &PrivateKey{d: ristretto255.NewScalar().Add(pk.d, r)}
}

// Sign returns a deterministic Schnorr signature of the given message using the given secret key.
func (pk *PrivateKey) Sign(message []byte) []byte {
	sigA, sigB := schnorr.Sign(pk.d, pk.PublicKey().q, message)

	return append(sigA, sigB...)
}

// DiffieHellman performs a Diffie-Hellman key exchange using the given public key.
func (pk *PrivateKey) DiffieHellman(pub *PublicKey) *ristretto255.Element {
	return ristretto255.NewElement().ScalarMult(pk.d, pub.q)
}

// PublicKey returns the public key for this private key without derivation.
func (pk *PrivateKey) PublicKey() *PublicKey {
	q := ristretto255.NewElement().ScalarBaseMult(pk.d)

	return &PublicKey{q: q}
}

// Encode returns the private key as a string of bytes.
func (pk *PrivateKey) Encode(b []byte) []byte {
	return pk.d.Encode(b)
}

// PublicKey is the public component of a key pair used to verify signatures.
type PublicKey struct {
	q *ristretto255.Element
}

// DecodePublicKey returns a PublicKey for the given encoded public key or, if the data is
// malformed, an error.
func DecodePublicKey(b []byte) (*PublicKey, error) {
	q := ristretto255.NewElement()
	if err := q.Decode(b); err != nil {
		return nil, err
	}

	return &PublicKey{q: q}, nil
}

// Encode returns the public key encoded as bytes.
func (pk *PublicKey) Encode(b []byte) []byte {
	return pk.q.Encode(b)
}

// Derive derives a PublicKey instance from the receiver using the given label.
func (pk *PublicKey) Derive(label string) *PublicKey {
	// Calculate the delta for the derived key.
	r := scaldf.Label([]byte(label))
	rG := ristretto255.NewElement().ScalarBaseMult(r)

	// Return the current public key plus the delta.
	return &PublicKey{q: ristretto255.NewElement().Add(pk.q, rG)}
}

// Verify returns true if the given signature of the given message was created with the private key
// corresponding to this public key.
func (pk *PublicKey) Verify(message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}

	return schnorr.Verify(pk.q, sig[:PublicKeySize], sig[PublicKeySize:], message)
}

// String returns the receiver's ristretto255 point encoded with base64.
func (pk *PublicKey) String() string {
	return pk.q.String()
}

var _ fmt.Stringer = &PublicKey{}

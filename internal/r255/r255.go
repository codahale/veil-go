// Package r255 provides ristretto255 functionality.
//
// Veil uses ristretto255 for asymmetric cryptography. Each person has a secret key from which
// multiple private/public key pairs can be derived.
//
// To derive a private key, a secret scalar is derived from the secret key using a scoped hash. A
// delta scalar is derived from an opaque label using another scoped hash and added to the secret
// scalar to produce a new private key.
//
// To derive a public key, the same delta scalar is derived, multiplied by the risotto255 base
// point, and added to the public key point.
//
// To sign messages, Veil creates Schnorr signatures using a private key derived from the signer's
// secret key and an ephemeral key derived from both the seceret key and the message.
package r255

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"github.com/codahale/veil/internal/scopedhash"
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
	// Read a large buffer of random data.
	b := make([]byte, SecretKeySize*4)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	// Hash the random data with SHA-512.
	r := sha512.Sum512(b)

	// Use the hash as a secret key.
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
	s := deriveScalar(scopedhash.NewSecretKeyHash(), sk.r)

	// Calculate the delta for the derived key.
	r := deriveScalar(scopedhash.NewDerivedKeyHash(), []byte(label))

	// Return the secret scalar plus the delta.
	return &PrivateKey{d: ristretto255.NewScalar().Add(s, r)}
}

// PublicKey derives a PublicKey instance from the receiver using the given label.
func (sk *SecretKey) PublicKey(label string) *PublicKey {
	return sk.PrivateKey(label).PublicKey()
}

// String returns the first 8 bytes of the SHA-512 hash of the secret key as a hexadecimal string.
// This uniquely identifies the secret key without revealing information about it.
func (sk *SecretKey) String() string {
	h := scopedhash.NewIdentityHash()
	_, _ = h.Write(sk.r)
	d := h.Sum(nil)

	return hex.EncodeToString(d[:8])
}

// Encode returns the secret key as a series of bytes.
func (sk *SecretKey) Encode(b []byte) []byte {
	return append(b, sk.r...)
}

var _ fmt.Stringer = &SecretKey{}

// PrivateKey is a ristretto255 scalar used to create signatures and shared secrets.
type PrivateKey struct {
	d *ristretto255.Scalar
}

// NewEphemeralKeys returns a new, random private key, unassociated with any secret key, and its
// corresponding public key.
func NewEphemeralKeys() (*PrivateKey, *PublicKey, error) {
	// Read a large buffer of random data.
	b := make([]byte, SecretKeySize*4)
	if _, err := rand.Read(b); err != nil {
		return nil, nil, err
	}

	// Hash it with SHA-512.
	h := sha512.Sum512(b)

	// Create a private key using the hash as a scalar.
	priv := &PrivateKey{d: ristretto255.NewScalar().FromUniformBytes(h[:])}

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
	r := deriveScalar(scopedhash.NewDerivedKeyHash(), []byte(label))

	return &PrivateKey{d: ristretto255.NewScalar().Add(pk.d, r)}
}

// Sign returns a deterministic Schnorr signature of the given message using the given secret key.
func (pk *PrivateKey) Sign(message []byte) []byte {
	// Create a deterministic nonce unique to the combination of private key and message by
	// calculating the scoped HMAC-SHA512 of the message using the encoded private key as the key.
	h := hmac.New(scopedhash.NewSignatureNonceHash, pk.d.Encode(nil))
	_, _ = h.Write(message)

	// Generate an ephemeral key pair (R, r) from the deterministic nonce.
	r := ristretto255.NewScalar().FromUniformBytes(h.Sum(nil))
	R := ristretto255.NewElement().ScalarBaseMult(r)
	Rb := R.Encode(nil)

	// Derive a scalar from the ephemeral public key and the message using SHA-512 (k).
	k := deriveScalar(scopedhash.NewSignatureHash(), append(Rb, message...))

	// Calculate the signature scalar (kd + r).
	s := ristretto255.NewScalar().Multiply(k, pk.d)
	s = s.Add(s, r)

	// Return the ephemeral public key and the signature scalar (R, s).
	return append(Rb, s.Encode(nil)...)
}

// DiffieHellman performs a Diffie-Hellman key exchange using the given public key.
func (pk *PrivateKey) DiffieHellman(pub *PublicKey) []byte {
	x := ristretto255.NewElement().ScalarMult(pk.d, pub.q)

	return x.Encode(nil)
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

// String returns the receiver's ristretto255 point encoded with base64.
func (pk *PublicKey) String() string {
	return pk.q.String()
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
	r := deriveScalar(scopedhash.NewDerivedKeyHash(), []byte(label))
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

	// Decode the ephemeral public key.
	R := ristretto255.NewElement()
	if err := R.Decode(sig[:PublicKeySize]); err != nil {
		return false
	}

	// Decode the signature scalar.
	s := ristretto255.NewScalar()
	if err := s.Decode(sig[PublicKeySize:]); err != nil {
		return false
	}

	// Derive a scalar from the ephemeral public key and the message.
	k := deriveScalar(scopedhash.NewSignatureHash(), append(sig[:PublicKeySize], message...))

	// R' = -kQ + gs
	ky := ristretto255.NewElement().ScalarMult(k, pk.q)
	Rp := ristretto255.NewElement().ScalarBaseMult(s)
	Rp = Rp.Subtract(Rp, ky)

	// The signature is verified R and R' are equal.
	return R.Equal(Rp) == 1
}

var _ fmt.Stringer = &PublicKey{}

// deriveScalar hashes the given data with SHA-512 and maps the digest to a scalar.
func deriveScalar(h hash.Hash, data []byte) *ristretto255.Scalar {
	_, _ = h.Write(data)

	return ristretto255.NewScalar().FromUniformBytes(h.Sum(nil))
}

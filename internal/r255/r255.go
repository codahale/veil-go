// Package r255 provides ristretto255 functionality.
//
// Veil uses ristretto255 for asymmetric cryptography. Each person has a ristretto255/XDH key pair
// and shares their public key with each other.
//
// To make authenticated messages, Veil creates Schnorr signatures using the signer's secret key.
// The actual "message" signed is a SHA-512 hash of the message, and SHA-512 is used to derive
// ristretto255 scalars from the message and ephemeral public key.
package r255

import (
	"crypto/rand"
	"crypto/sha512"
	"hash"

	"github.com/codahale/veil/internal/scopedhash"
	"github.com/gtank/ristretto255"
)

const (
	PublicKeySize = 32                 // PublicKeySize is the length of a public key in bytes.
	SecretKeySize = 64                 // SecretKeySize is the length of a secret key in bytes.
	SignatureSize = PublicKeySize + 32 // SignatureSize is the length of a signature in bytes.
)

// DiffieHellman performs a Diffie-Hellman key exchange using the given public key.
func DiffieHellman(sk, pk []byte) ([]byte, error) {
	// Derive the secret key.
	s := deriveScalar(scopedhash.NewSecretKeyHash(), sk)

	// Decode the public key.
	q, err := decodePoint(pk)
	if err != nil {
		return nil, err
	}

	// Multiply the point by the scalar.
	x := ristretto255.NewElement().ScalarMult(s, q)

	// Return the shared secret.
	return x.Encode(nil), nil
}

// PublicKey returns the corresponding public key for the given secret key.
func PublicKey(sk []byte) []byte {
	// Derive the secret key.
	s := deriveScalar(scopedhash.NewSecretKeyHash(), sk)

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(s)

	// Encode the public key and return.
	return q.Encode(nil)
}

// NewSecretKey creates a new 64-byte secret key.
func NewSecretKey() ([]byte, error) {
	// Read a large buffer of random data.
	b := make([]byte, SecretKeySize*4)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	// Hash it with SHA-512.
	h := sha512.Sum512(b)

	// Return the hash.
	return h[:], nil
}

// Sign returns a Schnorr signature of the given message using the given secret key.
func Sign(sk, message []byte) ([]byte, error) {
	// Create a new secret key.
	skR, err := NewSecretKey()
	if err != nil {
		return nil, err
	}

	// Generate an ephemeral key pair (R, r). The derivation step is skipped here because the secret
	// key is discarded after the signature is created.
	r := ristretto255.NewScalar().FromUniformBytes(skR)
	R := ristretto255.NewElement().ScalarBaseMult(r)
	Rb := R.Encode(nil)

	// Derive the static secret scalar.
	x := deriveScalar(scopedhash.NewSecretKeyHash(), sk)

	// Derive a scalar from the ephemeral public key and the message using SHA-512 (k).
	k := deriveScalar(scopedhash.NewSignatureHash(), append(Rb, message...))

	// Calculate the signature scalar (kx + r).
	s := ristretto255.NewScalar().Multiply(k, x)
	s = s.Add(s, r)

	// Return the ephemeral public key and the signature scalar (R, s).
	return append(Rb, s.Encode(nil)...), nil
}

// Verify returns true if the given signature of the given message was created with the secret key
// corresponding to the given public key.
func Verify(pk, message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}

	// Decode the static public key.
	y, err := decodePoint(pk)
	if err != nil {
		return false
	}

	// Decode the ephemeral public key.
	R, err := decodePoint(sig[:PublicKeySize])
	if err != nil {
		return false
	}

	// Decode the signature scalar.
	s, err := decodeScalar(sig[PublicKeySize:])
	if err != nil {
		panic(err)
	}

	// Derive a scalar from the ephemeral public key and the message.
	k := deriveScalar(scopedhash.NewSignatureHash(), append(sig[:PublicKeySize], message...))

	// R' = -ky + gs
	ky := ristretto255.NewElement().ScalarMult(k, y)
	Rp := ristretto255.NewElement().ScalarBaseMult(s)
	Rp = Rp.Subtract(Rp, ky)

	// The signature is verified R and R' are equal.
	return R.Equal(Rp) == 1
}

// deriveScalar hashes the given data with SHA-512 and maps the digest to a scalar.
func deriveScalar(h hash.Hash, data []byte) *ristretto255.Scalar {
	_, _ = h.Write(data)

	return ristretto255.NewScalar().FromUniformBytes(h.Sum(nil))
}

// decodePoint decodes the encoded point and returns it.
func decodePoint(data []byte) (*ristretto255.Element, error) {
	p := ristretto255.NewElement()
	if err := p.Decode(data); err != nil {
		return nil, err
	}

	return p, nil
}

// decodeScalar decodes the encoded scalar and returns it.
func decodeScalar(data []byte) (*ristretto255.Scalar, error) {
	s := ristretto255.NewScalar()
	if err := s.Decode(data); err != nil {
		return nil, err
	}

	return s, nil
}

// deriveSecretKey returns a scalar derived from the given secret key using the given label.
func deriveSecretKey(sk []byte, label string) *ristretto255.Scalar {
	// Derive the secret key.
	s := deriveScalar(scopedhash.NewSecretKeyHash(), sk)

	// Calculate the delta for the derived key.
	r := deriveScalar(scopedhash.NewDerivedKeyHash(), []byte(label))

	// Return the secret key plus the delta.
	return ristretto255.NewScalar().Add(s, r)
}

// derivePublicKey returns a point derived from the given public key using the given label which
// corresponds to the secret key produced by deriveSecretKey.
func derivePublicKey(pk []byte, label string) (*ristretto255.Element, error) {
	// Decode the public key.
	q, err := decodePoint(pk)
	if err != nil {
		return nil, err
	}

	// Calculate the delta for the derived key.
	r := deriveScalar(scopedhash.NewDerivedKeyHash(), []byte(label))
	rG := ristretto255.NewElement().ScalarBaseMult(r)

	// Return the secret key plus the delta.
	return ristretto255.NewElement().Add(q, rG), nil
}

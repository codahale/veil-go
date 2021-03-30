// Package r255 provides ristretto255 functionality.
//
// Veil uses ristretto255 for asymmetric cryptography. Each person has a ristretto255/XDH key pair
// and shares their public key with each other. In place of encoded ristretto255 points, Veil
// encodes all public keys using Elligator2, making them indistinguishable from noise.
//
// To make authenticated messages, Veil creates Schnorr signatures using the signer's secret key.
// The ephemeral public key created for the signature is encoded using Elligator2, making the
// signatures indistinguishable from random noise. The actual "message" signed is a SHA-512 hash of
// the message, and SHA-512 is used to derive ristretto255 scalars from the message and ephemeral
// public key.
package r255

import (
	"crypto/rand"
	"crypto/sha512"

	"github.com/gtank/ristretto255"
)

const (
	PublicKeySize = 32                 // PublicKeySize is the length of a public key in bytes.
	SecretKeySize = 64                 // SecretKeySize is the length of a secret key in bytes.
	SignatureSize = PublicKeySize + 32 // SignatureSize is the length of a signature in bytes.
)

// DiffieHellman performs a Diffie-Hellman key exchange using the given public key.
func DiffieHellman(sk, pk []byte) []byte {
	// Derive the secret key.
	s := deriveScalar(sk)

	// Decode the public key.
	q := decodePoint(pk)

	// Multiply the point by the scalar.
	x := ristretto255.NewElement().ScalarMult(s, q)

	// Return the shared secret.
	return x.Encode(nil)
}

// PublicKey returns the corresponding public key for the given secret key.
func PublicKey(sk []byte) []byte {
	// Derive the secret key.
	s := deriveScalar(sk)

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(s)

	// Encode the public key and return.
	return q.Encode(nil)
}

// GenerateKeys generates a key pair and returns the public key and the secret key.
func GenerateKeys() (sk, pk []byte, err error) {
	// Allocate a buffer for the secret key.
	sk = make([]byte, SecretKeySize)

	// Generate 64 random bytes.
	if _, err = rand.Read(sk); err != nil {
		return nil, nil, err
	}

	// Convert to a secret key by hashing it with SHA-512.
	s := deriveScalar(sk)

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(s)

	// Return the secret key and the public key.
	return sk, q.Encode(nil), nil
}

// Sign returns a Schnorr signature of the given message using the given secret key.
func Sign(sk, message []byte) ([]byte, error) {
	// Generate an ephemeral key pair (R, r).
	skE, R, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	// Derive the static and ephemeral secret keys (x, r).
	x := deriveScalar(sk)
	r := deriveScalar(skE)

	// Derive a scalar from the ephemeral public key and the message using SHA-512 (k).
	k := deriveScalar(append(R, message...))

	// Calculate the signature scalar (kx + r).
	s := ristretto255.NewScalar().Multiply(k, x)
	s = s.Add(s, r)

	// Return the ephemeral public key and the signature scalar (R, s).
	return append(R, s.Encode(nil)...), nil
}

// Verify returns true if the given signature of the given message was created with the secret key
// corresponding to the given public key.
func Verify(pk, message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}

	// Decode the static public key.
	y := decodePoint(pk)

	// Decode the ephemeral public key.
	R := decodePoint(sig[:PublicKeySize])

	// Decode the signature scalar.
	s := decodeScalar(sig[PublicKeySize:])

	// Derive a scalar from the ephemeral public key and the message.
	k := deriveScalar(append(sig[:PublicKeySize], message...))

	// R' = -ky + gs
	ky := ristretto255.NewElement().ScalarMult(k, y)
	Rp := ristretto255.NewElement().ScalarBaseMult(s)
	Rp = Rp.Subtract(Rp, ky)

	// The signature is verified R and R' are equal.
	return R.Equal(Rp) == 1
}

func deriveScalar(data []byte) *ristretto255.Scalar {
	h := sha512.Sum512(data)

	return ristretto255.NewScalar().FromUniformBytes(h[:])
}

func decodePoint(data []byte) *ristretto255.Element {
	p := ristretto255.NewElement()
	if err := p.Decode(data); err != nil {
		panic(err)
	}

	return p
}

func decodeScalar(data []byte) *ristretto255.Scalar {
	s := ristretto255.NewScalar()
	if err := s.Decode(data); err != nil {
		panic(err)
	}

	return s
}

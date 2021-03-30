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

	"github.com/bwesterb/go-ristretto"
)

const (
	PublicKeySize = 32                 // PublicKeySize is the length of a public key in bytes.
	SecretKeySize = 64                 // SecretKeySize is the length of a secret key in bytes.
	SignatureSize = PublicKeySize + 32 // SignatureSize is the length of a signature in bytes.
)

// DiffieHellman performs a Diffie-Hellman key exchange using the given public key.
func DiffieHellman(sk, pk []byte) []byte {
	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	// Derive the secret key.
	s.Derive(sk)

	// Decode the public key.
	_ = q.UnmarshalBinary(pk)

	// Multiply the point by the scalar.
	x := (&ristretto.Point{}).ScalarMult(&q, &s)

	// Return the shared secret.
	return x.Bytes()
}

// PublicKey returns the corresponding public key for the given secret key.
func PublicKey(sk []byte) []byte {
	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	// Derive the secret key.
	s.Derive(sk)

	// Calculate the public key.
	q.ScalarMultBase(&s)

	// Encode the public key and return.
	return q.Bytes()
}

// GenerateKeys generates a key pair and returns the public key and the secret key.
func GenerateKeys() (sk, pk []byte, err error) {
	// Allocate a buffer for the secret key.
	sk = make([]byte, SecretKeySize)

	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	// Generate 64 random bytes.
	if _, err = rand.Read(sk); err != nil {
		return nil, nil, err
	}

	// Convert to a secret key by hashing it with SHA-512.
	s.Derive(sk)

	// Calculate the public key.
	q.ScalarMultBase(&s)

	return sk, q.Bytes(), nil
}

// Sign returns a Schnorr signature of the given message using the given secret key.
func Sign(sk, message []byte) ([]byte, error) {
	var (
		x, r ristretto.Scalar
		k    ristretto.Scalar
		s    ristretto.Scalar
	)

	// Generate an ephemeral key pair (R, r).
	skE, R, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	// Derive the static and ephemeral secret keys (x, r).
	x.Derive(sk)
	r.Derive(skE)

	// Derive a scalar from the ephemeral public key and the message using SHA-512 (k).
	k.Derive(append(R, message...))

	// Calculate the signature scalar (kx + r).
	s.MulAdd(&k, &x, &r)

	// Return the ephemeral public key and the signature scalar (R, s).
	return append(R, s.Bytes()...), nil
}

// Verify returns true if the given signature of the given message was created with the secret key
// corresponding to the given public key.
func Verify(pk, message, sig []byte) bool {
	var (
		y  ristretto.Point
		R  ristretto.Point
		s  ristretto.Scalar
		k  ristretto.Scalar
		Rp ristretto.Point
		ky ristretto.Point
	)

	if len(sig) != SignatureSize {
		return false
	}

	// Decode the static public key.
	_ = y.UnmarshalBinary(pk)

	// Decode the ephemeral public key.
	_ = R.UnmarshalBinary(sig[:PublicKeySize])

	// Decode the signature scalar.
	_ = s.UnmarshalBinary(sig[PublicKeySize:])

	// Derive a scalar from the ephemeral public key and the message.
	k.Derive(append(sig[:PublicKeySize], message...))

	// R' = -ky + gs
	ky.ScalarMult(&y, &k)
	Rp.ScalarMultBase(&s)
	Rp.Sub(&Rp, &ky)

	// The signature is verified R and R' are equal.
	return R.Equals(&Rp)
}

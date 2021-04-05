// Package r255 provides ristretto255 functionality.
package r255

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols/rng"
	"github.com/gtank/ristretto255"
)

const (
	PublicKeySize  = 32 // PublicKeySize is the length of a public key in bytes.
	PrivateKeySize = 32 // PrivateKeySize is the length of a private key in bytes.
	SecretKeySize  = 64 // SecretKeySize is the length of a secret key in bytes.
)

// NewEphemeralKeys returns a new, random private key, unassociated with any secret key, and its
// corresponding public key.
func NewEphemeralKeys() (*ristretto255.Scalar, *ristretto255.Element, error) {
	var r [SecretKeySize]byte
	if _, err := rng.Read(r[:]); err != nil {
		return nil, nil, err
	}

	d := ristretto255.NewScalar().FromUniformBytes(r[:])

	return d, ristretto255.NewElement().ScalarBaseMult(d), nil
}

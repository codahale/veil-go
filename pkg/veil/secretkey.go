package veil

import (
	"encoding/hex"
	"fmt"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/rng"
	"github.com/codahale/veil/pkg/veil/internal/scaldf"
	"github.com/codahale/veil/pkg/veil/internal/skid"
	"github.com/gtank/ristretto255"
)

// SecretKey is a key that's used to derive PrivateKey instances (and thus PublicKey instances).
//
// It should never be serialized in plaintext. Use EncryptSecretKey to encrypt it using a
// passphrase.
type SecretKey struct {
	r [internal.UniformBytestringSize]byte
}

// NewSecretKey creates a new secret key.
func NewSecretKey() (*SecretKey, error) {
	var sk SecretKey

	// Generate a random 64-byte key.
	if _, err := rng.Read(sk.r[:]); err != nil {
		return nil, err
	}

	return &sk, nil
}

// PrivateKey returns a private key for the given key ID.
func (sk *SecretKey) PrivateKey(keyID string) *PrivateKey {
	d := scaldf.DeriveScalar(scaldf.SecretScalar(&sk.r), idSeparator)
	q := ristretto255.NewElement().ScalarBaseMult(d)
	root := PrivateKey{d: d, q: q}

	return root.Derive(keyID)
}

// PublicKey returns a public key for the given key ID.
func (sk *SecretKey) PublicKey(keyID string) *PublicKey {
	return sk.PrivateKey(keyID).PublicKey()
}

// String returns a safe identifier for the key.
func (sk *SecretKey) String() string {
	return hex.EncodeToString(skid.ID(&sk.r, 8))
}

var _ fmt.Stringer = &SecretKey{}

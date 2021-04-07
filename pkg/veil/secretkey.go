package veil

import (
	"crypto/rand"
	"fmt"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/scaldf"
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
	if _, err := rand.Read(sk.r[:]); err != nil {
		return nil, err
	}

	return &sk, nil
}

// PrivateKey returns a private key for the given key ID.
func (sk *SecretKey) PrivateKey(keyID string) *PrivateKey {
	return sk.root().Derive(keyID)
}

// PublicKey returns a public key for the given key ID.
func (sk *SecretKey) PublicKey(keyID string) *PublicKey {
	return sk.PrivateKey(keyID).PublicKey()
}

// String returns a safe identifier for the key.
func (sk *SecretKey) String() string {
	return sk.root().PublicKey().String()
}

// root returns the root private key, derived from the secret key using veil.scaldf.secret-key.
func (sk *SecretKey) root() *PrivateKey {
	d := scaldf.RootScalar(&sk.r)
	q := ristretto255.NewElement().ScalarBaseMult(d)

	return &PrivateKey{d: d, q: q}
}

var _ fmt.Stringer = &SecretKey{}

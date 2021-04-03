package veil

import (
	"fmt"

	"github.com/codahale/veil/pkg/veil/internal/r255"
)

// SecretKey is a key that's used to derive PrivateKey instances (and thus PublicKey instances).
//
// It should never be serialized in plaintext. Use EncryptSecretKey to encrypt it using a
// passphrase.
type SecretKey struct {
	k *r255.SecretKey
}

// NewSecretKey creates a new secret key.
func NewSecretKey() (*SecretKey, error) {
	sk, err := r255.NewSecretKey()
	if err != nil {
		return nil, err
	}

	return &SecretKey{k: sk}, nil
}

// PrivateKey returns a private key for the given key ID.
func (sk *SecretKey) PrivateKey(keyID string) *PrivateKey {
	root := PrivateKey{k: sk.k.PrivateKey(idSeparator)}

	return root.Derive(keyID)
}

// PublicKey returns a public key for the given key ID.
func (sk *SecretKey) PublicKey(keyID string) *PublicKey {
	root := PublicKey{k: sk.k.PublicKey(idSeparator)}

	return root.Derive(keyID)
}

// String returns a safe identifier for the key.
func (sk *SecretKey) String() string {
	return sk.k.String()
}

var _ fmt.Stringer = &SecretKey{}

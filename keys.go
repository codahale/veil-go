package veil

import (
	"encoding/base64"
	"fmt"

	"github.com/codahale/veil/internal/xdh"
)

// PublicKey is a ristretto255/XDH public key.
type PublicKey []byte

func (pk PublicKey) String() string {
	return base64.RawURLEncoding.EncodeToString(pk)
}

var _ fmt.Stringer = PublicKey{}

// SecretKey is a ristretto255/XDH secret key.
type SecretKey []byte

func (sk SecretKey) String() string {
	return sk.PublicKey().String()
}

// PublicKey returns the public key for the given secret key.
func (sk SecretKey) PublicKey() PublicKey {
	return xdh.PublicKey(sk)
}

// NewSecretKey creates a new secret key.
func NewSecretKey() (SecretKey, error) {
	_, sk, err := xdh.GenerateKeys()
	if err != nil {
		return nil, err
	}

	return sk, err
}

var _ fmt.Stringer = SecretKey{}

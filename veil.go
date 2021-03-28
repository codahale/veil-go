package veil

import (
	"encoding/base32"
	"fmt"

	"github.com/codahale/veil/internal/xdh"
)

// PublicKey is a ristretto255/XDH public key, encoded with Base32.
type PublicKey string

// SecretKey is a ristretto255/XDH secret key.
type SecretKey []byte

func (sk SecretKey) String() string {
	return string(sk.PublicKey())
}

// PublicKey returns the public key for the given secret key.
func (sk SecretKey) PublicKey() PublicKey {
	return encodePK(xdh.PublicKey(sk))
}

// NewSecretKey creates a new secret key.
func NewSecretKey() (SecretKey, error) {
	_, sk, err := xdh.GenerateKeys()
	return sk, err
}

var (
	_          fmt.Stringer = SecretKey{}
	pkEncoding              = base32.StdEncoding.WithPadding(base32.NoPadding) //nolint:gochecknoglobals // constant
)

func decodePK(pk PublicKey) ([]byte, error) {
	return pkEncoding.DecodeString(string(pk))
}

func encodePK(pk []byte) PublicKey {
	return PublicKey(pkEncoding.EncodeToString(pk))
}

func decodePKs(pks []PublicKey) ([][]byte, error) {
	keys := make([][]byte, len(pks))

	for i, pk := range pks {
		b, err := decodePK(pk)
		if err != nil {
			return nil, err
		}

		keys[i] = b
	}

	return keys, nil
}

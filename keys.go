package veil

import (
	"encoding"
	"encoding/base32"
	"fmt"

	"github.com/codahale/veil/internal/xdh"
)

// PublicKey is a ristretto255/XDH public key.
type PublicKey []byte

func (pk PublicKey) MarshalText() (text []byte, err error) {
	text = make([]byte, pkEncoding.EncodedLen(len(pk)))

	pkEncoding.Encode(text, pk)

	return
}

func (pk *PublicKey) UnmarshalText(text []byte) error {
	data := make([]byte, xdh.PublicKeySize)

	_, err := pkEncoding.Decode(data, text)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	*pk = data

	return nil
}

func (pk PublicKey) String() string {
	text, err := pk.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

var (
	_ encoding.TextMarshaler   = PublicKey{}
	_ encoding.TextUnmarshaler = &PublicKey{}
	_ fmt.Stringer             = PublicKey{}
)

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
	return sk, err
}

var (
	_ fmt.Stringer = SecretKey{}

	//nolint:gochecknoglobals // reusable constant
	pkEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

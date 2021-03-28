// Package veil implements the Veil hybrid cryptosystem.
//
// Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
// authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
// Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
// encrypted. As a result, a global passive adversary would be unable to gain any information from a
// Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
// true length, and fake recipients can be added to disguise their true number from other
// recipients.
//
// You should not use this.
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

	//nolint:gochecknoglobals // reusable constant
	pkEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
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

var _ fmt.Stringer = SecretKey{}

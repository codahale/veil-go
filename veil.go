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
//
// Technically, it's the Elligator2 encoding of a ristretto255 point and is indistinguishable from
// random noise. It can be marshalled and unmarshalled as a base32 string for human consumption.
type PublicKey []byte

// MarshalText encodes the public key into unpadded base32 text and returns the result.
func (pk PublicKey) MarshalText() (text []byte, err error) {
	text = make([]byte, pkEncoding.EncodedLen(len(pk)))

	pkEncoding.Encode(text, pk)

	return
}

// UnmarshalText decodes the results of MarshalText and updates the receiver to contain the decoded
// public key.
func (pk *PublicKey) UnmarshalText(text []byte) error {
	data := make([]byte, xdh.PublicKeySize)

	_, err := pkEncoding.Decode(data, text)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	*pk = data

	return nil
}

// String returns the public key as unpadded base32 text.
func (pk PublicKey) String() string {
	text, err := pk.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// SecretKey is a ristretto255/XDH secret key.
//
// Technically, it's a ristretto255 scalar. It should never be serialized in plaintext. Use
// EncryptSecretKey to encrypt it using a passphrase.
type SecretKey []byte

// String returns the secret key's corresponding public key as unpadded base32 text.
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
	_ encoding.TextMarshaler   = PublicKey{}
	_ encoding.TextUnmarshaler = &PublicKey{}
	_ fmt.Stringer             = PublicKey{}
	_ fmt.Stringer             = SecretKey{}

	//nolint:gochecknoglobals // reusable constant
	pkEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

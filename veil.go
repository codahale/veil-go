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

	"github.com/codahale/veil/internal/r255"
)

// SecretKey is a key that's used to sign and decrypt messages.
//
// It should never be serialized in plaintext. Use EncryptSecretKey to encrypt it using a
// passphrase.
type SecretKey struct {
	k *r255.SecretKey
}

// String returns a safe identifier for the key.
func (sk *SecretKey) String() string {
	return sk.k.String()
}

// PublicKey returns a public key for the given label.
func (sk *SecretKey) PublicKey(label string) *PublicKey {
	return &PublicKey{k: sk.k.PublicKey(label)}
}

// NewSecretKey creates a new secret key.
func NewSecretKey() (*SecretKey, error) {
	sk, err := r255.NewSecretKey()
	if err != nil {
		return nil, err
	}

	return &SecretKey{k: sk}, nil
}

var _ fmt.Stringer = &SecretKey{}

// PublicKey is a key that's used to verify and encrypt messages.
//
// It can be marshalled and unmarshalled as a base32 string for human consumption.
type PublicKey struct {
	k *r255.PublicKey
}

// MarshalText encodes the public key into unpadded base32 text and returns the result.
func (pk *PublicKey) MarshalText() (text []byte, err error) {
	b := pk.k.Encode(nil)

	text = make([]byte, asciiEncoding.EncodedLen(len(b)))

	asciiEncoding.Encode(text, b)

	return
}

// UnmarshalText decodes the results of MarshalText and updates the receiver to contain the decoded
// public key.
func (pk *PublicKey) UnmarshalText(text []byte) error {
	data := make([]byte, r255.PublicKeySize)

	// Decode from base32.
	_, err := asciiEncoding.Decode(data, text)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Decode as a ristretto255 point.
	k, err := r255.DecodePublicKey(data)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	pk.k = k

	return nil
}

// String returns the public key as unpadded base32 text.
func (pk *PublicKey) String() string {
	text, err := pk.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

var (
	_ encoding.TextMarshaler   = &PublicKey{}
	_ encoding.TextUnmarshaler = &PublicKey{}
	_ fmt.Stringer             = &PublicKey{}

	//nolint:gochecknoglobals // reusable constant
	asciiEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

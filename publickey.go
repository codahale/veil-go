package veil

import (
	"encoding"
	"fmt"

	"github.com/codahale/veil/internal/r255"
)

// PublicKey is a key that's used to verify and encrypt messages.
//
// It can be marshalled and unmarshalled as a base32 string for human consumption.
type PublicKey struct {
	k *r255.PublicKey
}

// Derive derives a PublicKey from the receiver with the given sub-key ID.
func (pk *PublicKey) Derive(subKeyID string) *PublicKey {
	key := pk.k

	for _, id := range splitID(subKeyID) {
		key = key.Derive(id)
	}

	return &PublicKey{k: key}
}

// String returns the public key as unpadded base32 text.
func (pk *PublicKey) String() string {
	text, err := pk.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalBinary encodes the public key into a 32-byte slice.
func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.k.Encode(nil), nil
}

// UnmarshalBinary decodes the public key from a 32-byte slice.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	k, err := r255.DecodePublicKey(data)
	if err != nil {
		return err
	}

	pk.k = k

	return nil
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

var (
	_ encoding.BinaryMarshaler   = &PublicKey{}
	_ encoding.BinaryUnmarshaler = &PublicKey{}
	_ encoding.TextMarshaler     = &PublicKey{}
	_ encoding.TextUnmarshaler   = &PublicKey{}
	_ fmt.Stringer               = &PublicKey{}
)

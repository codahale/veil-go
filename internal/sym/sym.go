package sym

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize   // KeySize is the size of AEAD keys in bytes.
	NonceSize = chacha20poly1305.NonceSize // NonceSize is the size of AEAD nonces in bytes.
	TagSize   = poly1305.TagSize           // TagSize is the size of AEAD tags in bytes.
)

// NewAEAD returns a new AEAD using the given key.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

package veil

import (
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

// keyRatchet implements a symmetric key ratchet system based on HKDF-SHA2-512/256.
type keyRatchet struct {
	chainKey  []byte
	outputKey []byte
	nonce     []byte
}

const (
	aesKeySize = 32
)

// newKeyRatchet returns a new keyRatchet instance.
func newKeyRatchet(key []byte) *keyRatchet {
	chainKey := make([]byte, aesKeySize)
	copy(chainKey, key)

	return &keyRatchet{
		chainKey:  chainKey,
		outputKey: make([]byte, aesKeySize),
		nonce:     make([]byte, gcmNonceSize),
	}
}

// ratchet returns the next key and nonce in the sequence. The previous chain key is used to create
// a new HKDF-SHA2-512/256 instance with a domain-specific information parameter. If this is the
// final key in the sequence, a salt of "last" is used; otherwise, a salt of "next" is used. The
// first N bytes of KDF output are used to create a new chain key; the next 32 and 12 bytes of KDF
// output are returned as the next key and nonce, respectively.
func (kr *keyRatchet) ratchet(final bool) ([]byte, []byte) {
	salt := []byte("next")
	if final {
		// If this is the final key/nonce in the sequence, use a different salt.
		salt = []byte("last")
	}

	// Create a new HKDF-SHA2-512/256 instance with the current chain key, the salt, and a
	// domain-specific info parameter.
	kdf := hkdf.New(sha512.New512_256, kr.chainKey, salt, []byte("veil-ratchet"))

	// Use the first 32 bytes as the next chain key.
	_, _ = io.ReadFull(kdf, kr.chainKey)

	// After that, use 32 bytes as the next encryption key.
	_, _ = io.ReadFull(kdf, kr.outputKey)

	// After that, use 12 bytes as the next encryption nonce.
	_, _ = io.ReadFull(kdf, kr.nonce)

	// Return the new key and nonce.
	return kr.outputKey, kr.nonce
}

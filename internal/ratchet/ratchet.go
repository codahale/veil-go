package ratchet

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Sequence implements a symmetric key ratchet system based on HKDF-SHA2-256.
type Sequence struct {
	chainKey  []byte
	outputKey []byte
}

const (
	KeySize = 64 // KeySize is the size of a ratchet sequence key in bytes.
)

// New returns a new Sequence instance which uses the initial key to create a sequence of keys of
// size n.
func New(key []byte, n int) *Sequence {
	chainKey := make([]byte, KeySize)
	copy(chainKey, key)

	return &Sequence{
		chainKey:  chainKey,
		outputKey: make([]byte, n),
	}
}

// Next returns the next key in the sequence. The previous chain key is used to create a new
// HKDF-SHA2-256 instance with a domain-specific information parameter. If this is the final key in
// the sequence, a salt of "last" is used; otherwise, a salt of "next" is used. The first 64 bytes
// of KDF output are used to create a new chain key; the next N bytes of KDF output are returned as
// the next key.
func (kr *Sequence) Next(final bool) []byte {
	salt := []byte("next")
	if final {
		// If this is the final key/IV in the sequence, use a different salt.
		salt = []byte("last")
	}

	// Create a new HKDF-SHA2-256 instance with the current chain key, the salt, and a
	// domain-specific info parameter.
	kdf := hkdf.New(sha256.New, kr.chainKey, salt, []byte("veil-ratchet"))

	// Use the first 64 bytes as the next chain key.
	_, _ = io.ReadFull(kdf, kr.chainKey)

	// After that, use N bytes as the next encryption key.
	_, _ = io.ReadFull(kdf, kr.outputKey)

	// Return the new key.
	return kr.outputKey
}

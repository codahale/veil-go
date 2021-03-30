// Package ratchet implements an HKDF-based key ratchet system.
//
// In order to encrypt arbitrarily large messages, Veil uses a streaming AEAD construction based on
// a Signal-style HKDF ratchet. An initial 64-byte chain key is used to create an HKDF-SHA-512
// instance, and the first 64 bytes of its output are used to create a new chain key. The next N
// bytes of KDF output are used to create the key and nonce for an AEAD. To prevent attacker
// appending blocks to a message, the final block of a stream is keyed using a different salt, thus
// permanently forking the chain.
package ratchet

import (
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Sequence implements a symmetric key ratchet system based on HKDF-SHA-512.
type Sequence struct {
	buf []byte
}

const (
	KeySize = 64 // KeySize is the size of a ratchet sequence key in bytes.
)

// New returns a new Sequence instance which uses the initial key to create a sequence of keys of
// size n.
func New(key []byte, n int) *Sequence {
	buf := make([]byte, KeySize+n)
	copy(buf, key)

	return &Sequence{buf: buf}
}

// Next returns the next key in the sequence. The previous chain key is used to create a new
// HKDF-SHA-512 instance with a domain-specific information parameter. If this is the final key in
// the sequence, a salt of "last" is used; otherwise, a salt of "next" is used. The first 64 bytes
// of KDF output are used to create a new chain key; the next N bytes of KDF output are returned as
// the next key.
func (kr *Sequence) Next(final bool) []byte {
	salt := []byte("next")
	if final {
		// If this is the final key in the sequence, use a different salt.
		salt = []byte("last")
	}

	// Create a new HKDF-SHA-512 instance with the current chain key, the salt, and a
	// domain-specific info parameter.
	kdf := hkdf.New(sha512.New, kr.buf[:KeySize], salt, []byte("veil-ratchet"))

	// Advance the ratchet.
	if _, err := io.ReadFull(kdf, kr.buf); err != nil {
		panic(err)
	}

	// Return the new key.
	return kr.buf[KeySize:]
}

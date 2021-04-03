// Package ratchet implements an KDF-based key ratchet system.
//
// In order to encrypt arbitrarily large messages, Veil uses a streaming AEAD construction based on
// a Signal-style KDF ratchet. An initial 64-byte chain key is used to create a domain-specific KDF
// instance, and the first 64 bytes of its output are used to create a new chain key. The next N
// bytes of KDF output are used to create the key and nonce for an AEAD. To prevent attacker
// appending blocks to a message, the final block of a stream is keyed using a different salt, thus
// permanently forking the chain.
package ratchet

import (
	"github.com/codahale/veil/pkg/veil/internal/dxof"
)

// Sequence implements a symmetric key ratchet system based on an XOF.
type Sequence struct {
	xof dxof.XOF
	key []byte
	out []byte
}

const (
	KeySize = 64 // KeySize is the size of a ratchet sequence key in bytes.
)

// New returns a new Sequence instance which uses the initial key to create a sequence of keys.
func New(key []byte, n int) *Sequence {
	// Create a new XOF instance with the key.
	xof := dxof.RatchetShakeHash(key)

	// Generate a new ratchet key from the output.
	k := make([]byte, KeySize)
	_, _ = xof.Read(k)

	// Create a new sequence.
	s := &Sequence{
		xof: xof,
		key: k,
		out: make([]byte, n),
	}

	return s
}

// Next returns the next key in the sequence. The XOF is reset and reseeded with the ratchet key
// generated during the last iteration. If this is the final block, the XOF is finalized by writing
// `veil-final` to it. The first 64 bytes of XOF output are used to create a new chain key; the next
// N bytes of XOF output are returned as the next key.
func (kr *Sequence) Next(final bool) []byte {
	// Reset the XOF to its original state.
	kr.xof.Reset()

	// Reseed the XOF with the ratchet key.
	_, _ = kr.xof.Write(kr.key)

	// Finalize the XOF if needed.
	if final {
		_, _ = kr.xof.Write([]byte("veil-final"))
	}

	// Generate a new ratchet key.
	_, _ = kr.xof.Read(kr.key)

	// Generate a new output key.
	_, _ = kr.xof.Read(kr.out)

	return kr.out
}

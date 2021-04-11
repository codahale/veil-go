// Package internal contains various helper functions for writing STROBE protocols.
//
// The subpackages of internal contain all the various STROBE protocols Veil uses.
package internal

import (
	"crypto/rand"
	"math/big"

	"github.com/mr-tron/base58"
)

const (
	// MessageKeySize is the symmetric message key size in bytes.
	MessageKeySize = 32

	// TagSize is the authentication tag size in bytes.
	TagSize = 16

	// ElementSize is the length of an encoded ristretto255 element.
	ElementSize = 32

	// ScalarSize is the length of an encoded ristretto255 scalar.
	ScalarSize = 32

	// UniformBytestringSize is the length of a uniform bytestring which can be mapped to either a
	// ristretto255 element or scalar.
	UniformBytestringSize = 64
)

// IntN returns a cryptographically random integer selected uniformly from [0,max).
func IntN(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}

	return int(n.Int64()), nil
}

// ASCIIEncode returns the given data, encoded in base58.
func ASCIIEncode(data []byte) []byte {
	return []byte(base58.Encode(data))
}

// ASCIIDecode decodes the given base58 text.
func ASCIIDecode(text []byte) ([]byte, error) {
	return base58.Decode(string(text))
}

// SliceForAppend takes a slice and a requested number of bytes. It returns a slice with the
// contents of the given slice followed by that many bytes and a second slice that aliases into it
// and contains only the extra bytes. If the original slice has sufficient capacity then no
// allocation is performed.
func SliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}

	tail = head[len(in):]

	return
}

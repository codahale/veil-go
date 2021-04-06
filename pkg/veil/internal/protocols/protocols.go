// Package protocols contains various helper functions for writing STROBE protocols.
//
// The subpackages of protocols contain all the various STROBE protocols Veil uses.
package protocols

import (
	"encoding/binary"

	"github.com/sammyne/strobe"
)

const (
	ElementSize = 32 // ElementSize is the length of an encoded ristretto255 element.
	ScalarSize  = 32 // ScalarSize is the length of an encoded ristretto255 scalar.

	// UniformBytestringSize is the length of a uniform bytestring which can be mapped to either a
	// ristretto255 element or scalar.
	UniformBytestringSize = 64

	// RatchetSize determines the amount of state to reset during each ratchet.
	//
	//     Setting L = sec/8 bytes is sufficient when R ≥ sec/8. That is, set L to 16 bytes or 32
	//     bytes for Strobe-128/b and Strobe-256/b, respectively.
	RatchetSize = int(strobe.Bit256) / 8
)

// LittleEndianU32 returns n as a 32-bit little endian bit string.
func LittleEndianU32(n int) []byte {
	var b [4]byte

	binary.LittleEndian.PutUint32(b[:], uint32(n))

	return b[:]
}

// New instantiates a new STROBE protocol with the given name and a 256-bit security level.
func New(proto string) *strobe.Strobe {
	s, err := strobe.New(proto, strobe.Bit256)
	if err != nil {
		panic(err)
	}

	return s
}

// Must panics if the given error is not nil.
func Must(err error) {
	if err != nil {
		panic(err)
	}
}

// MustENC ignores the given byte slice and panics if the given error is not nil.
func MustENC(_ []byte, err error) {
	if err != nil {
		panic(err)
	}
}

// Copy returns a copy of the given slice for keying protocols without modifying arguments.
func Copy(b []byte) []byte {
	c := make([]byte, len(b))

	copy(c, b)

	return c
}

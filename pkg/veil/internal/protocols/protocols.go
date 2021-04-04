// Package protocols contains various helper functions for writing STROBE protocols.
//
// The subpackages of protocols contain all the various STROBE protocols Veil uses.
package protocols

import (
	"encoding/binary"

	"github.com/sammyne/strobe"
)

// BigEndianU32 returns n as a 32-bit big endian bit string.
func BigEndianU32(n int) []byte {
	var b [4]byte

	binary.BigEndian.PutUint32(b[:], uint32(n))

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

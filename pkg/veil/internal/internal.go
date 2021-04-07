// Package internal contains various helper functions for writing STROBE protocols.
//
// The subpackages of internal contain all the various STROBE protocols Veil uses.
package internal

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

const (
	ElementSize = 32 // ElementSize is the length of an encoded ristretto255 element.
	ScalarSize  = 32 // ScalarSize is the length of an encoded ristretto255 scalar.
	KeySize     = 32 // KeySize is the symmetric key size in bytes.
	TagSize     = 16 // TagSize is the authentication tag size in bytes.

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

// Strobe instantiates a new STROBE protocol with the given name and a 256-bit security level.
func Strobe(proto string) *strobe.Strobe {
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

// IntN returns a cryptographically random integer selected uniformly from [0,max).
func IntN(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}

	return int(n.Int64())
}

// NewEphemeralKeys returns a new, random private key, unassociated with any secret key, and its
// corresponding public key.
func NewEphemeralKeys() (*ristretto255.Scalar, *ristretto255.Element) {
	var r [UniformBytestringSize]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}

	d := ristretto255.NewScalar().FromUniformBytes(r[:])

	return d, ristretto255.NewElement().ScalarBaseMult(d)
}

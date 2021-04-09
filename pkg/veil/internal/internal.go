// Package internal contains various helper functions for writing STROBE protocols.
//
// The subpackages of internal contain all the various STROBE protocols Veil uses.
package internal

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"math/big"

	"github.com/sammyne/strobe"
)

const (
	// KeySize is the symmetric key size in bytes.
	KeySize = 32

	// TagSize is the authentication tag size in bytes.
	TagSize = 16

	// BlockSize is the recommended block size for streams, as selected by it looking pretty.
	BlockSize = 64 * 1024 // 64KiB

	// RatchetSize determines the amount of state to reset during each ratchet.
	//
	//     Setting L = sec/8 bytes is sufficient when R ≥ sec/8. That is, set L to 16 bytes or 32
	//     bytes for Strobe-128/b and Strobe-256/b, respectively.
	RatchetSize = int(strobe.Bit256) / 8

	// ElementSize is the length of an encoded ristretto255 element.
	ElementSize = 32

	// ScalarSize is the length of an encoded ristretto255 scalar.
	ScalarSize = 32

	// UniformBytestringSize is the length of a uniform bytestring which can be mapped to either a
	// ristretto255 element or scalar.
	UniformBytestringSize = 64
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
func IntN(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}

	return int(n.Int64()), nil
}

// ASCIIEncode returns the given data, encoded in base32.
func ASCIIEncode(data []byte) []byte {
	text := make([]byte, asciiEncoding.EncodedLen(len(data)))

	asciiEncoding.Encode(text, data)

	return text
}

// ASCIIDecode decodes the given base32 text.
func ASCIIDecode(text []byte) ([]byte, error) {
	data := make([]byte, asciiEncoding.DecodedLen(len(text)))

	n, err := asciiEncoding.Decode(data, text)
	if err != nil {
		return nil, err
	}

	return data[:n], nil
}

//nolint:gochecknoglobals // reusable constant
var asciiEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

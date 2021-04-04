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

func New(proto string) *strobe.Strobe {
	s, err := strobe.New(proto, strobe.Bit256)
	if err != nil {
		panic(err)
	}

	return s
}

func Must(err error) {
	if err != nil {
		panic(err)
	}
}

func MustENC(_ []byte, err error) {
	if err != nil {
		panic(err)
	}
}

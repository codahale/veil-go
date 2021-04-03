package protocols

import "encoding/binary"

// BigEndianU32 returns n as a 32-bit big endian bit string.
func BigEndianU32(n int) []byte {
	var b [4]byte

	binary.BigEndian.PutUint32(b[:], uint32(n))

	return b[:]
}

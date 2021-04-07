// Package balloon implements memory-hard Balloon Hashing via STROBE.
//
// Hashes are generated as follows, given a passphrase P, salt S, space parameter X, time parameter
// T, and key size N:
//
//     INIT('veil.kdf.balloon',  level=256)
//     AD(LE_U32(X), meta=true)
//     AD(LE_U32(T), meta=true)
//     AD(LE_U32(N), meta=true)
//     KEY(P)
//     AD(S)
//
// Then, for each iteration of the balloon hashing algorithm, given a counter C, a left block L, and
// a right block R:
//
//     AD(LE_U64(C))
//     AD(L)
//     AD(R)
//     PRF(N)
//
// It should be noted that there is no standard balloon hashing algorithm, so this protocol is in
// the very, very tall grass of cryptography and should never be used.
package balloon

import (
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/sammyne/strobe"
)

// DeriveKey returns an n-byte key of the given password.
func DeriveKey(passphrase, salt []byte, space, time, n int) []byte {
	n += n % 2 // round up

	// Initialize a new protocol.
	balloon := internal.Strobe("veil.balloon")

	// Include the space parameter as associated data.
	internal.Must(balloon.AD(internal.LittleEndianU32(space), &strobe.Options{Meta: true}))

	// Include the time parameter as associated data.
	internal.Must(balloon.AD(internal.LittleEndianU32(time), &strobe.Options{Meta: true}))

	// Include the size parameter as associated data.
	internal.Must(balloon.AD(internal.LittleEndianU32(n), &strobe.Options{Meta: true}))

	// Key the protocol with the passphrase.
	internal.Must(balloon.KEY(internal.Copy(passphrase), false))

	// Include the salt as associated data.
	internal.Must(balloon.AD(salt, &strobe.Options{}))

	// Allocate a 64-bit counter and a buffer for its encoding.
	var (
		ctr    uint64
		ctrBuf [8]byte
	)

	// Allocate an index block.
	idx := make([]byte, n)

	// Allocate blocks.
	buf := make([]byte, space*n)

	// Initialize first block.
	hashCounter(balloon, &ctr, ctrBuf[:], buf[0:n], nil, nil)

	// Initialize all other blocks.
	for m := 1; m < space-1; m++ {
		hashCounter(balloon, &ctr, ctrBuf[:], buf[(m*n):(m*n)+n], buf[(m-1)*n:(m-1)*n+n], nil)
	}

	// Mix buffer contents.
	for t := 1; t < time; t++ {
		for m := 1; m < space; m++ {
			// Hash last and current blocks.
			j := (m - 1) % space
			hashCounter(balloon, &ctr, ctrBuf[:], buf[m*n:m*n+n], buf[j*n:j*n+n], buf[m*n:m*n+n])

			// Hash pseudo-randomly chosen blocks.
			for i := 0; i < delta; i++ {
				// Map indexes to a block and hash it and the salt.
				binary.LittleEndian.PutUint32(idx[0:], uint32(t))
				binary.LittleEndian.PutUint32(idx[4:], uint32(m))
				binary.LittleEndian.PutUint32(idx[8:], uint32(i))
				hashCounter(balloon, &ctr, ctrBuf[:], idx, salt, idx)

				// Map the hashed index block back to an index and hash that block.
				other := int(binary.LittleEndian.Uint64(idx) % uint64(space))
				hashCounter(balloon, &ctr, ctrBuf[:], buf[m*n:m*n+n], buf[other*n:other*n+n], nil)
			}
		}
	}

	return buf[(space-1)*n:]
}

func hashCounter(s *strobe.Strobe, ctr *uint64, ctrBuf, dst, left, right []byte) {
	// Increment the counter.
	*ctr++

	// Encode the counter as a little-endian value.
	binary.LittleEndian.PutUint64(ctrBuf, *ctr)

	// Hash the counter.
	internal.Must(s.AD(ctrBuf, &strobe.Options{}))

	// Hash the left block.
	internal.Must(s.AD(left, &strobe.Options{}))

	// Hash the right block.
	internal.Must(s.AD(right, &strobe.Options{}))

	// Extract a new block.
	internal.Must(s.PRF(dst, false))
}

const (
	delta = 3 // Delta is the number of dependencies per block.
)

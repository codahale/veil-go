// Package balloon implements memory-hard Balloon Hashing via STROBE.
//
// Hashes are generated as follows, given a passphrase P, salt S, space parameter X, time parameter
// T, and digest size N:
//
//     INIT('veil.balloon',  level=256)
//     AD(BIG_ENDIAN_U32(X), meta=true)
//     AD(BIG_ENDIAN_U32(T), meta=true)
//     AD(BIG_ENDIAN_U32(N), meta=true)
//     KEY(P)
//     AD(S)
//
// Then, for each iteration of the balloon hashing algorithm, given a counter C, a left block L, and
// a right block R:
//
//     AD(BIG_ENDIAN_U64(C))
//     AD(L)
//     AD(R)
//     PRF(N)
//
// It should be noted that there is no standard balloon hashing algorithm, so this protocol is in
// the very, very tall grass of cryptography and should never be used.
package balloon

import (
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

// Hash returns an n-byte hash of the given password.
func Hash(passphrase, salt []byte, space, time uint32, n int) []byte {
	n += n % 2 // round up

	// Initialize a new protocol.
	balloon := protocols.New("veil.balloon")

	// Include the space parameter as associated data.
	protocols.Must(balloon.AD(protocols.BigEndianU32(int(space)), &strobe.Options{Meta: true}))

	// Include the time parameter as associated data.
	protocols.Must(balloon.AD(protocols.BigEndianU32(int(time)), &strobe.Options{Meta: true}))

	// Include the size parameter as associated data.
	protocols.Must(balloon.AD(protocols.BigEndianU32(n), &strobe.Options{Meta: true}))

	// Key the protocol with the passphrase.
	protocols.Must(balloon.KEY(passphrase, false))

	// Include the salt as associated data.
	protocols.Must(balloon.AD(salt, &strobe.Options{}))

	// Allocate a 64-bit counter and a buffer for its encoding.
	var ctr uint64
	var ctrBuf [8]byte

	// Allocate an index block.
	idx := make([]byte, n)

	// Allocate blocks.
	buf := make([][]byte, space)
	for i := range buf {
		buf[i] = make([]byte, n)
	}

	// Initialize first block.
	hashCounter(balloon, &ctr, ctrBuf[:], buf[0], nil, nil)

	// Initialize all other blocks.
	for m := uint32(1); m < space-1; m++ {
		hashCounter(balloon, &ctr, ctrBuf[:], buf[m], buf[m-1], nil)
	}

	// Mix buffer contents.
	for t := uint32(1); t < time; t++ {
		for m := uint32(1); m < space; m++ {
			// Hash last and current blocks.
			prev := buf[(m-1)%space]
			hashCounter(balloon, &ctr, ctrBuf[:], buf[m], prev, buf[m])

			// Hash pseudorandomly chosen blocks.
			for i := 0; i < delta; i++ {
				// Map indexes to a block and hash it and the salt.
				binary.BigEndian.PutUint32(idx[0:], t)
				binary.BigEndian.PutUint32(idx[4:], m)
				binary.BigEndian.PutUint32(idx[8:], uint32(i))
				hashCounter(balloon, &ctr, ctrBuf[:], idx, salt, idx)

				// Map the hashed index block back to an index and hash that block.
				other := int(binary.BigEndian.Uint64(idx) % uint64(space))
				hashCounter(balloon, &ctr, ctrBuf[:], buf[m], buf[other], nil)
			}
		}
	}

	return buf[space-1]
}

func hashCounter(s *strobe.Strobe, ctr *uint64, ctrBuf []byte, dst, left, right []byte) {
	// Increment the counter.
	*ctr = *ctr + 1

	// Encode the counter as a big-endian value.
	binary.BigEndian.PutUint64(ctrBuf, *ctr)

	// Hash the counter.
	protocols.Must(s.AD(ctrBuf, &strobe.Options{}))

	// Hash the left block.
	protocols.Must(s.AD(left, &strobe.Options{}))

	// Hash the right block.
	protocols.Must(s.AD(right, &strobe.Options{}))

	// Extract a new block.
	protocols.Must(s.PRF(dst, false))
}

const (
	delta = 3 // Delta is the number of dependencies per block.
)

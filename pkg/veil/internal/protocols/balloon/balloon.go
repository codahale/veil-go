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
//     AD(BIG_ENDIAN_U32(C))
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

	cnt := 0
	idx := make([]byte, n)

	// Allocate buffers.
	buf := make([][]byte, space)
	for i := range buf {
		buf[i] = make([]byte, n)
	}

	// Initialize first block.
	cnt++
	hashCounter(balloon, cnt, buf[0], nil, nil)

	// Initialize all other blocks.
	for m := uint32(1); m < space-1; m++ {
		cnt++
		hashCounter(balloon, cnt, buf[m], buf[m-1], nil)
	}

	// Mix buffer contents.
	for t := uint32(1); t < time; t++ {
		// Hash last and current blocks.
		for m := uint32(1); m < space; m++ {
			prev := buf[(m-1)%space]
			cnt++
			hashCounter(balloon, cnt, buf[m], prev, buf[m])

			// Hash pseudorandomly chosen blocks.
			for i := 0; i < delta; i++ {
				binary.BigEndian.PutUint32(idx[0:], t)
				binary.BigEndian.PutUint32(idx[4:], m)
				binary.BigEndian.PutUint32(idx[8:], uint32(i))

				cnt++
				hashCounter(balloon, cnt, idx, salt, idx)

				other := int(binary.BigEndian.Uint64(idx) % uint64(space))

				cnt++
				hashCounter(balloon, cnt, buf[m], buf[other], nil)
			}
		}
	}

	return buf[space-1]
}

func hashCounter(s *strobe.Strobe, cnt int, dst, left, right []byte) {
	// Hash the counter.
	protocols.Must(s.AD(protocols.BigEndianU32(cnt), &strobe.Options{}))

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

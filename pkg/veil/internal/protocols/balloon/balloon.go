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

//nolint:gocognit,gocyclo,cyclop // it's supposed to be hard
// Hash returns an n-byte hash of the given password.
func Hash(passphrase, salt []byte, space, time uint32, n int) []byte {
	n += n % 2 // round up

	s, err := strobe.New("veil.balloon", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	// Include the space parameter as associated data.
	if err := s.AD(protocols.BigEndianU32(int(space)), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Include the time parameter as associated data.
	if err := s.AD(protocols.BigEndianU32(int(time)), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Include the size parameter as associated data.
	if err := s.AD(protocols.BigEndianU32(n), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Key the protocol with the passphrase.
	if err := s.KEY(passphrase, false); err != nil {
		panic(err)
	}

	// Include the salt as associated data.
	if err := s.AD(salt, &strobe.Options{}); err != nil {
		panic(err)
	}

	cnt := 0
	idx := make([]byte, n)

	// Allocate buffers.
	buf := make([][]byte, space)
	for i := range buf {
		buf[i] = make([]byte, n)
	}

	// Initialize first block.
	cnt++
	hashCounter(s, cnt, buf[0], nil, nil)

	// Initialize all other blocks.
	for m := uint32(1); m < space-1; m++ {
		cnt++
		hashCounter(s, cnt, buf[m], buf[m-1], nil)
	}

	// Mix buffer contents.
	for t := uint32(1); t < time; t++ {
		// Hash last and current blocks.
		for m := uint32(1); m < space; m++ {
			prev := buf[(m-1)%space]
			cnt++
			hashCounter(s, cnt, buf[m], prev, buf[m])

			// Hash pseudorandomly chosen blocks.
			for i := 0; i < delta; i++ {
				binary.BigEndian.PutUint32(idx[0:], t)
				binary.BigEndian.PutUint32(idx[4:], m)
				binary.BigEndian.PutUint32(idx[8:], uint32(i))

				cnt++
				hashCounter(s, cnt, idx, salt, idx)

				other := int(binary.BigEndian.Uint64(idx) % uint64(space))

				cnt++
				hashCounter(s, cnt, buf[m], buf[other], nil)
			}
		}
	}

	return buf[space-1]
}

func hashCounter(s *strobe.Strobe, cnt int, dst, left, right []byte) {
	// Hash the counter.
	if err := s.AD(protocols.BigEndianU32(cnt), &strobe.Options{}); err != nil {
		panic(err)
	}

	// Hash the left block.
	if err := s.AD(left, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Hash the right block.
	if err := s.AD(right, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Extract a new block.
	if err := s.PRF(dst, false); err != nil {
		panic(err)
	}
}

const (
	delta = 3 // Delta is the number of dependencies per block.
)

// Package stream provides the underlying STROBE protocol for Veil's RNG.
//
// At startup, a STROBE protocol is initialized:
//
//     INIT('veil.rng', level=256)
//
// When a block of random data is required, a block B of equivalent size is read from the host
// machine's RNG, and the following operations performed:
//
//     AD(LE_U64(LEN(B)), meta=true)
//     KEY(B)
//     PRF(LEN(B)) -> B
//     RATCHET(32)
//
// This insulates Veil somewhat against compromised RNGs, but at the end of the day this is still a
// deterministic process.
package rng

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// IntN returns a cryptographically random integer selected uniformly from [0,max).
func IntN(max int) int {
	n, err := rand.Int(Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}

	return int(n.Int64())
}

// Read is a helper function that calls Reader.Read using io.ReadFull. On return, n == len(b) if and
// only if err == nil.
func Read(b []byte) (int, error) {
	return io.ReadFull(Reader, b)
}

//nolint:gochecknoglobals // need a singleton
// Reader is a global, shared instance of a cryptographically secure random number generator.
var Reader io.Reader = &reader{rng: internal.Strobe("veil.rng")}

type reader struct {
	rng    *strobe.Strobe
	lenBuf [8]byte
}

func (r *reader) Read(p []byte) (n int, err error) {
	// Include length of PRF request as associated data.
	binary.LittleEndian.PutUint64(r.lenBuf[:], uint64(len(p)))
	internal.Must(r.rng.AD(r.lenBuf[:], &strobe.Options{Meta: true}))

	// Read a new block of data from the underlying RNG.
	if _, err := rand.Read(p); err != nil {
		return 0, err
	}

	// Re-key the protocol with the block.
	internal.Must(r.rng.KEY(p, false))

	// Return the results of the PRF.
	internal.Must(r.rng.PRF(p, false))

	// Ratchet the state of the RNG to prevent rollback.
	internal.Must(r.rng.RATCHET(internal.RatchetSize))

	return len(p), nil
}

// NewEphemeralKeys returns a new, random private key, unassociated with any secret key, and its
// corresponding public key.
func NewEphemeralKeys() (*ristretto255.Scalar, *ristretto255.Element, error) {
	var r [internal.UniformBytestringSize]byte
	if _, err := Read(r[:]); err != nil {
		return nil, nil, err
	}

	d := ristretto255.NewScalar().FromUniformBytes(r[:])

	return d, ristretto255.NewElement().ScalarBaseMult(d), nil
}

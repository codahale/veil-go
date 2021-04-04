// Package stream provides the underlying STROBE protocol for Veil's RNG.
//
// At startup, a STROBE protocol is initialized:
//
//     INIT('veil.rng', level=256)
//
// When a block of random data is required, a block B of equivalent size is read from the host
// machine's RNG, and the following operations performed:
//
//     AD(B)
//     PRF(LEN(B)) -> B
//
// This insulates Veil somewhat against compromised RNGs, but at the end of the day this is still a
// deterministic process.
package rng

import (
	"crypto/rand"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

// Read is a helper function that calls Reader.Read using io.ReadFull. On return, n == len(b) if and
// only if err == nil.
func Read(b []byte) (int, error) {
	return io.ReadFull(Reader, b)
}

//nolint:gochecknoglobals // need a singleton
// Reader is a global, shared instance of a cryptographically secure random number generator.
var Reader io.Reader = &reader{rng: protocols.New("veil.rng")}

type reader struct {
	rng *strobe.Strobe
}

func (r *reader) Read(p []byte) (n int, err error) {
	// Read a new block of data from the underlying RNG.
	if _, err := rand.Read(p); err != nil {
		return 0, err
	}

	// Include it as associated data.
	protocols.Must(r.rng.AD(p, &strobe.Options{}))

	// Return the results of the PRF.
	protocols.Must(r.rng.PRF(p, false))

	// Ratchet the state of the RNG to prevent rollback.
	protocols.Must(r.rng.RATCHET(protocols.RatchetSize))

	return len(p), nil
}

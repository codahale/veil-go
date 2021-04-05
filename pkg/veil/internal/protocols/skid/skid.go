// Package skid provides the underlying STROBE protocol for Veil's secret key IDs.
//
// ID generation is performed as follows, given a secret key K and ID size N:
//
//     INIT('veil.skid', level=256)
//     AD(LE_U32(N)),    meta=true)
//     KEY(K)
//     PRF(N)
package skid

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/sammyne/strobe"
)

// ID returns a safe identifier for the secret key which is n bytes long.
func ID(secretKey *[r255.UniformBytestringSize]byte, n int) []byte {
	skid := protocols.New("veil.skid")

	protocols.Must(skid.AD(protocols.LittleEndianU32(n), &strobe.Options{Meta: true}))

	k := make([]byte, len(secretKey))
	copy(k, secretKey[:])

	protocols.Must(skid.KEY(k, false))

	id := make([]byte, n)
	protocols.Must(skid.PRF(id, false))

	return id
}

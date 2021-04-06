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
	"github.com/sammyne/strobe"
)

// ID returns a safe identifier for the secret key which is n bytes long.
func ID(secretKey *[protocols.UniformBytestringSize]byte, n int) []byte {
	skid := protocols.New("veil.skid")

	protocols.Must(skid.AD(protocols.LittleEndianU32(n), &strobe.Options{Meta: true}))

	protocols.Must(skid.KEY(protocols.Copy(secretKey[:]), false))

	id := make([]byte, n)
	protocols.Must(skid.PRF(id, false))

	return id
}

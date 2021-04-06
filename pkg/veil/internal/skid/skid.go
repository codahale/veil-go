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
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/sammyne/strobe"
)

// ID returns a safe identifier for the secret key which is n bytes long.
func ID(secretKey *[internal.UniformBytestringSize]byte, n int) []byte {
	skid := internal.Strobe("veil.skid")

	internal.Must(skid.AD(internal.LittleEndianU32(n), &strobe.Options{Meta: true}))

	internal.Must(skid.KEY(internal.Copy(secretKey[:]), false))

	id := make([]byte, n)
	internal.Must(skid.PRF(id, false))

	return id
}

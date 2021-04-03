// Package skid provides the underlying STROBE protocol for Veil's secret key IDs.
//
// ID generation is performed as follows, given a secret key K and ID size N:
//
//     INIT('veil.skid',      level=256)
//     AD(BIG_ENDIAN_U32(N)), meta=true)
//     KEY(K)
//     PRF(N)
package skid

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

// ID returns a safe identifier for the secret key which is n bytes long.
func ID(secretKey []byte, n int) []byte {
	s, err := strobe.New("veil.skid", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	if err := s.AD(protocols.BigEndianU32(n), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	k := make([]byte, len(secretKey))
	copy(k, secretKey)

	if err := s.KEY(k, false); err != nil {
		panic(err)
	}

	id := make([]byte, n)
	if err := s.PRF(id, false); err != nil {
		panic(err)
	}

	return id
}

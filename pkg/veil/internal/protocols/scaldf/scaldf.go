// Package scaldf provides the underlying STROBE protocols for Veil's various scalar derivation
// functions, which derive ristretto255 scalars from other pieces of data.
//
// Label scalars are generated as follows, given a label L:
//
//     INIT('veil.scaldf.label', level=256)
//     KEY(L)
//     PRF(64)
//
// SecretKey scalars are generated as follows, given a secret key K:
//
//     INIT('veil.scaldf.secret-key', level=256)
//     KEY(K)
//     PRF(64)
package scaldf

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/gtank/ristretto255"
)

func Label(l []byte) *ristretto255.Scalar {
	var buf [64]byte

	label := protocols.New("veil.scaldf.label")

	k := make([]byte, len(l))
	copy(k, l)

	protocols.Must(label.KEY(k, false))

	protocols.Must(label.PRF(buf[:], false))

	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

func SecretKey(r []byte) *ristretto255.Scalar {
	var buf [64]byte

	secretKey := protocols.New("veil.scaldf.secret-key")

	k := make([]byte, len(r))
	copy(k, r)

	protocols.Must(secretKey.KEY(k, false))

	protocols.Must(secretKey.PRF(buf[:], false))

	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

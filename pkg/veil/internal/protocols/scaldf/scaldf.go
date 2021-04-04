// Package scaldf provides the underlying STROBE protocols for Veil's various scalar derivation
// functions, which derive ristretto255 scalars from other pieces of data.
//
// Scalars are generated as follows, given a protocol name P and datum D:
//
//     INIT(P, level=256)
//     KEY(D)
//     PRF(64)
//
// The three recognized protocol identifiers are:
//
// * `veil.scaldf.label`, used to derive scalars from labels
// * `veil.scaldf.secret-key`, used to derive secret scalars from secret keys
// * `veil.scaldf.random`, used to derive ephemeral scalars from PRNG data
package scaldf

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/gtank/ristretto255"
)

func Label(l []byte) *ristretto255.Scalar {
	return scalarDF("veil.scaldf.label", l)
}

func SecretKey(r []byte) *ristretto255.Scalar {
	return scalarDF("veil.scaldf.secret-key", r)
}

func Random(r []byte) *ristretto255.Scalar {
	return scalarDF("veil.scaldf.random", r)
}

func scalarDF(proto string, l []byte) *ristretto255.Scalar {
	var buf [64]byte

	label := protocols.New(proto)

	k := make([]byte, len(l))
	copy(k, l)

	protocols.Must(label.KEY(k, false))

	protocols.Must(label.PRF(buf[:], false))

	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

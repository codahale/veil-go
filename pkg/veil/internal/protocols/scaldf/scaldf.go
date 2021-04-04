// Package scaldf provides the underlying STROBE protocols for Veil's various scalar derivation
// functions, which derive ristretto255 scalars from various pieces of data.
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
	"github.com/sammyne/strobe"
)

type ScalarDerivationFunc func(dst *[64]byte, src []byte)

func Label() ScalarDerivationFunc {
	return func(dst *[64]byte, label []byte) {
		s, err := strobe.New("veil.scaldf.label", strobe.Bit256)
		if err != nil {
			panic(err)
		}

		k := make([]byte, len(label))
		copy(k, label)

		if err := s.KEY(k, false); err != nil {
			panic(err)
		}

		if err := s.PRF(dst[:], false); err != nil {
			panic(err)
		}
	}
}

func SecretKey() ScalarDerivationFunc {
	return func(dst *[64]byte, r []byte) {
		s, err := strobe.New("veil.scaldf.secret-key", strobe.Bit256)
		if err != nil {
			panic(err)
		}

		k := make([]byte, len(r))
		copy(k, r)

		if err := s.KEY(k, false); err != nil {
			panic(err)
		}

		if err := s.PRF(dst[:], false); err != nil {
			panic(err)
		}
	}
}

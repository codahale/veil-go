// Package scaldf provides the underlying STROBE protocols for Veil's various scalar derivation
// functions, which derive ristretto255 scalars from various pieces of data.
//
// SignatureNonce scalars are generated as follows, given a private key D and message M:
//
//     INIT('veil.scaldf.signature-nonce', level=256)
//     KEY(D)
//     AD(M)
//     PRF(64)
//
// Signature scalars are generated as follows, given a public key Q and message digest H:
//
//     INIT('veil.scaldf.signature', level=256)
//     KEY(Q)
//     AD(H)
//     PRF(64)
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
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

type ScalarDerivationFunc func(dst *[64]byte, src []byte)

func SignatureNonce(d *ristretto255.Scalar) ScalarDerivationFunc {
	return func(dst *[64]byte, message []byte) {
		s, err := strobe.New("veil.scaldf.signature-nonce", strobe.Bit256)
		if err != nil {
			panic(err)
		}

		if err := s.KEY(d.Encode(nil), false); err != nil {
			panic(err)
		}

		if err := s.AD(message, &strobe.Options{}); err != nil {
			panic(err)
		}

		if err := s.PRF(dst[:], false); err != nil {
			panic(err)
		}
	}
}

func Signature(q *ristretto255.Element) ScalarDerivationFunc {
	return func(dst *[64]byte, digest []byte) {
		s, err := strobe.New("veil.scaldf.signature", strobe.Bit256)
		if err != nil {
			panic(err)
		}

		if err := s.KEY(q.Encode(nil), false); err != nil {
			panic(err)
		}

		if err := s.AD(digest, &strobe.Options{}); err != nil {
			panic(err)
		}

		if err := s.PRF(dst[:], false); err != nil {
			panic(err)
		}
	}
}

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

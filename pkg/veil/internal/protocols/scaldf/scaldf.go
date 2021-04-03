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

		if err := s.AD(d.Encode(nil), &strobe.Options{}); err != nil {
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

		if err := s.AD(q.Encode(nil), &strobe.Options{}); err != nil {
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

		if err := s.AD(label, &strobe.Options{}); err != nil {
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

		if err := s.AD(r, &strobe.Options{}); err != nil {
			panic(err)
		}

		if err := s.PRF(dst[:], false); err != nil {
			panic(err)
		}
	}
}

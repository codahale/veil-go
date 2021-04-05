// Package scaldf provides the underlying STROBE protocols for Veil's various scalar derivation
// functions, which derive ristretto255 scalars from other pieces of data.
//
// Scalars are generated as follows, given a protocol name P and datum D:
//
//     INIT(P, level=256)
//     KEY(D)
//     PRF(64)
//
// The two recognized protocol identifiers are:
//
// * `veil.scaldf.label`, used to derive scalars from labels
// * `veil.scaldf.secret`, used to derive secret scalars from secret keys
package scaldf

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
)

// SecretScalar derives a secret scalar from the given bytestring.
func SecretScalar(r []byte) *ristretto255.Scalar {
	return scalarDF("veil.scaldf.secret", r)
}

// DeriveElement securely derives a child element from a parent element given a label. Without the
// label, the parent cannot be derived from the child.
func DeriveElement(q *ristretto255.Element, label string) *ristretto255.Element {
	// Calculate the delta for the derived element.
	r := scalarDF("veil.scaldf.label", []byte(label))
	rG := ristretto255.NewElement().ScalarBaseMult(r)

	// Return the current public key plus the delta.
	return ristretto255.NewElement().Add(q, rG)
}

// DeriveScalar securely derives a child scalar from a parent scalar given a label. Without the
// label, the parent cannot be derived from the child.
func DeriveScalar(d *ristretto255.Scalar, label string) *ristretto255.Scalar {
	// Calculate the delta for the derived scalar.
	r := scalarDF("veil.scaldf.label", []byte(label))

	return ristretto255.NewScalar().Add(d, r)
}

func scalarDF(proto string, l []byte) *ristretto255.Scalar {
	var buf [r255.UniformBytestringSize]byte

	label := protocols.New(proto)

	k := make([]byte, len(l))
	copy(k, l)

	protocols.Must(label.KEY(k, false))

	protocols.Must(label.PRF(buf[:], false))

	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

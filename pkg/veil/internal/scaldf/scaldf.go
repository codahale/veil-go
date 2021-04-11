// Package scaldf provides the underlying STROBE protocols for Veil's scalar derivation functions,
// which derive ristretto255 scalars from other pieces of data.
//
// Scalars are generated as follows, given a protocol name P and datum D:
//
//     INIT(P, level=256)
//     KEY(D)
//     PRF(64)
//
// The two recognized protocol identifiers are:
//
// * `veil.scaldf.label`, used to derive delta scalars from labels
// * `veil.scaldf.root`, used to derive root scalars from secret keys
package scaldf

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/gtank/ristretto255"
)

// RootScalar derives a root scalar from the given bytestring.
func RootScalar(r *[internal.UniformBytestringSize]byte) *ristretto255.Scalar {
	return scalarDF("veil.scaldf.root", r[:])
}

// DeriveElement securely derives a child element from a parent element given a label. Without the
// label, the parent cannot be derived from the child.
func DeriveElement(q *ristretto255.Element, label string) *ristretto255.Element {
	// Calculate the delta for the derived element.
	r := scalarDF("veil.scaldf.label", []byte(label))
	rG := ristretto255.NewElement().ScalarBaseMult(r)

	// Return the given element plus the delta element.
	return ristretto255.NewElement().Add(q, rG)
}

// DeriveScalar securely derives a child scalar from a parent scalar given a label. Without the
// label, the parent cannot be derived from the child.
func DeriveScalar(d *ristretto255.Scalar, label string) *ristretto255.Scalar {
	// Calculate the delta for the derived scalar.
	r := scalarDF("veil.scaldf.label", []byte(label))

	// Return the given scalar plus the delta scalar.
	return ristretto255.NewScalar().Add(d, r)
}

func scalarDF(proto string, data []byte) *ristretto255.Scalar {
	var buf [internal.UniformBytestringSize]byte

	// Initialize the protocol.
	scaldf := protocol.New(proto)

	// Key the protocol with a copy of the given data.
	scaldf.Key(data)

	// Generate 64 bytes of PRF output.
	scaldf.PRF(buf[:])

	// Map the PRF output to a scalar.
	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

package scaldf

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
)

func TestDerivation(t *testing.T) {
	t.Parallel()

	d0 := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x89}, internal.UniformBytestringSize))
	q0 := ristretto255.NewElement().ScalarBaseMult(d0)

	// Derive the scalar and element in parallel.
	d1 := DeriveScalar(d0, "one")
	q1 := DeriveElement(q0, "one")

	// Calculate what the element should be.
	q1p := ristretto255.NewElement().ScalarBaseMult(d1)

	assert.Equal(t, "derived elements", q1p.String(), q1.String())

	// Derive an element with a different label.
	if qX := DeriveElement(q0, "two"); qX.Equal(q1) == 1 {
		t.Errorf("%s and %s should not be equal", qX, q1)
	}

	// Derive a scalar with a different label.
	if dX := DeriveScalar(d0, "two"); dX.Equal(d1) == 1 {
		t.Errorf("%s and %s should not be equal", dX, d1)
	}
}

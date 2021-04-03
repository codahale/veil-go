package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSignature_MarshalText(t *testing.T) {
	t.Parallel()

	var s Signature
	if err := s.UnmarshalBinary([]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine")); err != nil {
		t.Fatal(err)
	}

	text, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "marshalled text",
		[]byte("MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSWC6LFNRWG653TOVRG2YLSNFXGKYLZ"+
			"MVWGY33XON2WE3LBOJUW4ZI"), text)
}

func TestSignature_UnmarshalText(t *testing.T) {
	t.Parallel()

	var s Signature
	if err := s.UnmarshalText([]byte("MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSWC6LFNRW" +
		"G653TOVRG2YLSNFXGKYLZMVWGY33XON2WE3LBOJUW4ZI")); err != nil {
		t.Fatal(err)
	}

	b, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshalled key",
		[]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine"), b)
}

func TestSignature_String(t *testing.T) {
	t.Parallel()

	var s Signature
	if err := s.UnmarshalBinary([]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine")); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation",
		"MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSWC6LFNRWG653TOVRG2YLSNFXGKYLZMVWGY33XON2WE3LBOJUW4ZI",
		s.String())
}

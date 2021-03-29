package veil

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("ok there bud")

	sig, err := sk.Sign(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}

	if err := sk.PublicKey().Verify(bytes.NewReader(message), sig); err != nil {
		t.Fatal(err)
	}
}

func TestSignature_MarshalText(t *testing.T) {
	t.Parallel()

	s := Signature("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine")

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

	//goland:noinspection GoNilness
	if err := s.UnmarshalText([]byte("MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSWC6LFNRW" +
		"G653TOVRG2YLSNFXGKYLZMVWGY33XON2WE3LBOJUW4ZI")); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshalled key",
		Signature("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine"), s)
}

func TestSignature_String(t *testing.T) {
	t.Parallel()

	s := Signature("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine")

	assert.Equal(t, "string representation",
		"MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSWC6LFNRWG653TOVRG2YLSNFXGKYLZMVWGY33XON2WE3LBOJUW4ZI",
		s.String())
}

package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPublicKey_MarshalText(t *testing.T) {
	t.Parallel()

	pk := PublicKey("ayellowsubmarineayellowsubmarine")

	text, err := pk.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "marshalled text",
		[]byte("MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSQ"), text)
}

func TestPublicKey_UnmarshalText(t *testing.T) {
	t.Parallel()

	var pk PublicKey

	//goland:noinspection GoNilness
	if err := pk.UnmarshalText([]byte("MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSQ")); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshalled key", PublicKey("ayellowsubmarineayellowsubmarine"), pk)
}

func TestPublicKey_String(t *testing.T) {
	t.Parallel()

	pk := PublicKey("ayellowsubmarineayellowsubmarine")

	assert.Equal(t, "string representation",
		"MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSQ", pk.String())
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation", sk.PublicKey().String(), sk.String())
}

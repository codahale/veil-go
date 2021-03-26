package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPublicKey_String(t *testing.T) {
	t.Parallel()

	pk := PublicKey("ayellowsubmarineayellowsubmarine")

	assert.Equal(t, "string representation",
		"YXllbGxvd3N1Ym1hcmluZWF5ZWxsb3dzdWJtYXJpbmU", pk.String())
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation", sk.PublicKey().String(), sk.String())
}

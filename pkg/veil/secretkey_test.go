package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSecretKey_PublicKey(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abc := s.PublicKey("/a").Derive("b").Derive("c")
	abcP := s.PublicKey("/a/b/c")

	assert.Equal(t, "derived key", abc.String(), abcP.String())
}

func TestSecretKey_PrivateKey(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abc := s.PrivateKey("/a").Derive("b").Derive("c")
	abcP := s.PrivateKey("/a/b/c")

	assert.Equal(t, "derived key", abc.PublicKey().String(), abcP.PublicKey().String())
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	var sk SecretKey

	copy(sk.r[:], "ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine")

	assert.Equal(t, "string representation",
		"ACSC8Phz7fzhtjHXH8JLG9KHfHZ4SkqEJhUW3Ci6FNAr", sk.String())
}

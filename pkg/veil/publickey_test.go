package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPublicKey_Derive(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abcd := s.PublicKey("/a/b/c/d")
	abcdP := s.PublicKey("/a/b").Derive("/c/d")

	assert.Equal(t, "derived key", abcd.String(), abcdP.String())
}

func TestPublicKey_UnmarshalText(t *testing.T) {
	t.Parallel()

	text := "164abzy93kqFFgkcMbJvgH2JgYHXKSLuESEQzCwv6wK"

	var in PublicKey
	if err := in.UnmarshalText([]byte(text)); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "round trip", text, in.String())
}

func TestPublicKey_MarshalText(t *testing.T) {
	t.Parallel()

	want := []byte(`164abzy93kqFFgkcMbJvgH2JgYHXKSLuESEQzCwv6wK`)

	var in PublicKey
	if err := in.UnmarshalText(want); err != nil {
		t.Fatal(err)
	}

	got, err := in.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "round trip", want, got)
}

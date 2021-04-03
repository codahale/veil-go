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

	abcd := s.PublicKey("/a/b/c/d").k
	abcdP := s.PublicKey("/a/b").Derive("/c/d").k

	assert.Equal(t, "derived key", abcd.String(), abcdP.String())
}

func TestPublicKey_UnmarshalText(t *testing.T) {
	t.Parallel()

	base32 := "ZJ756O23HCIC455GWQU24GJI3JHZGGYYZH3HDBWHGHQH3ZNTJMCQ"

	var in PublicKey
	if err := in.UnmarshalText([]byte(base32)); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "round trip", base32, in.String())
}

func TestPublicKey_MarshalText(t *testing.T) {
	t.Parallel()

	want := []byte("ZJ756O23HCIC455GWQU24GJI3JHZGGYYZH3HDBWHGHQH3ZNTJMCQ")

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

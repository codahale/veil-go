package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPrivateKey_Derive(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abcd := s.PrivateKey("/a/b/c/d").k
	abcdP := s.PrivateKey("/a/b").Derive("/c/d").k

	assert.Equal(t, "derived key", abcd.PublicKey().String(), abcdP.PublicKey().String())
}

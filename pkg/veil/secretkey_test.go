package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal/r255"
)

func TestSecretKey_PublicKey(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abc := s.k.PublicKey("/").Derive("a").Derive("b").Derive("c")
	abcP := s.PublicKey("/a/b/c").k

	assert.Equal(t, "derived key", abc.String(), abcP.String())
}

func TestSecretKey_PrivateKey(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abc := s.k.PrivateKey("/").Derive("a").Derive("b").Derive("c")
	abcP := s.PrivateKey("/a/b/c").k

	assert.Equal(t, "derived key", abc.PublicKey().String(), abcP.PublicKey().String())
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	k, err := r255.DecodeSecretKey([]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine"))
	if err != nil {
		t.Fatal(err)
	}

	sk := &SecretKey{
		k: k,
	}

	assert.Equal(t, "string representation", "6e6eb0f19c5f456e", sk.String())
}

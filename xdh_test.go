package veil

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestXDH(t *testing.T) {
	t.Parallel()

	skA := make([]byte, 32)
	skB := make([]byte, 32)

	if _, err := io.ReadFull(rand.Reader, skA); err != nil {
		t.Fatal(err)
	}

	if _, err := io.ReadFull(rand.Reader, skB); err != nil {
		t.Fatal(err)
	}

	pkA := sk2pk(skA)
	pkB := sk2pk(skB)

	xA, err := xdh(skA, pkB)
	if err != nil {
		t.Fatal(err)
	}

	xB, err := xdh(skB, pkA)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "shared secret", xA, xB)
}

func TestRepresentativeTransform(t *testing.T) {
	t.Parallel()

	sk := make([]byte, 32)

	if _, err := io.ReadFull(rand.Reader, sk); err != nil {
		t.Fatal(err)
	}

	pk, rk, err := sk2pkrk(sk)
	if err != nil {
		t.SkipNow()
	}

	pk2 := rk2pk(rk)

	assert.Equal(t, "public key", pk, pk2)
}

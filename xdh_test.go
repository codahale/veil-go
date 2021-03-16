package veil

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/codahale/gubbins/assert"
)

func TestXDH(t *testing.T) {
	t.Parallel()

	var skA, skB ristretto.Scalar

	skA.Rand()
	skB.Rand()

	pkA := sk2pk(&skA)
	pkB := sk2pk(&skB)

	xA, err := xdh(&skA, &pkB)
	if err != nil {
		t.Fatal(err)
	}

	xB, err := xdh(&skB, &pkA)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "shared secret", xA, xB)
}

func TestRepresentativeTransform(t *testing.T) {
	t.Parallel()

	var sk ristretto.Scalar

	sk.Rand()

	pk := sk2pk(&sk)

	rk, err := pk2rk(&pk)
	if err != nil {
		t.SkipNow()
	}

	pk2 := rk2pk(rk)

	assert.Equal(t, "public key", pk.Bytes(), pk2.Bytes())
}

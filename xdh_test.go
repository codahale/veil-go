package veil

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/internal/xdh"
)

func TestRepresentativeTransform(t *testing.T) {
	t.Parallel()

	var (
		sk      ristretto.Scalar
		pk, pk2 ristretto.Point
	)

	sk.Rand()
	xdh.SecretToPublic(&pk, &sk)

	rk := xdh.PublicToRepresentative(&pk)
	if rk == nil {
		t.Skipf("%s has no representative", sk)
	}

	xdh.RepresentativeToPublic(&pk2, rk)

	assert.Equal(t, "public key", pk.Bytes(), pk2.Bytes())
}

func TestKemExchange(t *testing.T) {
	t.Parallel()

	pkA, _, skA, err := xdh.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	pkB, _, skB, err := xdh.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	rkW, keyA, ivA, err := kemSend(&skA, &pkA, &pkB, true)
	if err != nil {
		t.Fatal(err)
	}

	keyB, ivB := kemReceive(&skB, &pkB, &pkA, rkW, true)

	assert.Equal(t, "key", keyA, keyB)
	assert.Equal(t, "iv", ivA, ivB)
}

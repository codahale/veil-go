package xdh

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/codahale/gubbins/assert"
)

func TestSharedSecret(t *testing.T) {
	t.Parallel()

	var (
		skA, skB ristretto.Scalar
		pkA, pkB ristretto.Point
	)

	skA.Rand()
	skB.Rand()

	SecretToPublic(&pkA, &skA)
	SecretToPublic(&pkB, &skB)

	xA := SharedSecret(&skA, &pkB)
	xB := SharedSecret(&skB, &pkA)

	assert.Equal(t, "shared secret", xA, xB)
}

func TestRepresentativeTransform(t *testing.T) {
	t.Parallel()

	var (
		sk      ristretto.Scalar
		pk, pk2 ristretto.Point
	)

	sk.Rand()
	SecretToPublic(&pk, &sk)

	rk := PublicToRepresentative(&pk)
	if rk == nil {
		t.Skipf("%s has no representative", sk)
	}

	RepresentativeToPublic(&pk2, rk)

	assert.Equal(t, "public key", pk.Bytes(), pk2.Bytes())
}

func BenchmarkGenerateKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, _ = GenerateKeys()
	}
}

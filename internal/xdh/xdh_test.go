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

func BenchmarkGenerateKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, _ = GenerateKeys()
	}
}

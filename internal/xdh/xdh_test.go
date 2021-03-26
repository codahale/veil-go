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

func BenchmarkPublicToRepresentative(b *testing.B) {
	q, _, _, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		PublicToRepresentative(&q)
	}
}

func BenchmarkRepresentativeToPublic(b *testing.B) {
	_, rk, _, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	var q ristretto.Point

	for i := 0; i < b.N; i++ {
		RepresentativeToPublic(&q, rk)
	}
}

func BenchmarkSecretToPublic(b *testing.B) {
	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	s.Rand()

	for i := 0; i < b.N; i++ {
		SecretToPublic(&q, &s)
	}
}

func BenchmarkSharedSecret(b *testing.B) {
	_, _, skA, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	pkA, _, _, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		SharedSecret(&skA, &pkA)
	}
}

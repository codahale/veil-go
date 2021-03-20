package veil

import (
	"crypto/rand"
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/codahale/gubbins/assert"
)

func TestXDH(t *testing.T) {
	t.Parallel()

	var (
		skA, skB ristretto.Scalar
		pkA, pkB ristretto.Point
	)

	skA.Rand()
	skB.Rand()

	sk2pk(&skA, &pkA)
	sk2pk(&skB, &pkB)

	xA := xdh(&skA, &pkB)
	xB := xdh(&skB, &pkA)

	assert.Equal(t, "shared secret", xA, xB)
}

func TestRepresentativeTransform(t *testing.T) {
	t.Parallel()

	var (
		sk      ristretto.Scalar
		pk, pk2 ristretto.Point
	)

	sk.Rand()
	sk2pk(&sk, &pk)

	rk := pk2rk(&pk)
	if rk == nil {
		t.Skipf("%s has no representative", sk)
	}

	rk2pk(rk, &pk2)

	assert.Equal(t, "public key", pk.Bytes(), pk2.Bytes())
}

func TestKemExchange(t *testing.T) {
	t.Parallel()

	pkA, _, skA, err := generateKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkB, _, skB, err := generateKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("ok")

	rkW, keyA, nonceA, err := kemSend(rand.Reader, &skA, &pkA, &pkB, data)
	if err != nil {
		t.Fatal(err)
	}

	keyB, nonceB := kemReceive(&skB, &pkB, &pkA, rkW, data)

	assert.Equal(t, "key", keyA, keyB)
	assert.Equal(t, "nonce", nonceA, nonceB)
}

func BenchmarkGenerateKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, _ = generateKeys(rand.Reader)
	}
}

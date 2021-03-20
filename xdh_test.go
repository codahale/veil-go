package veil

import (
	"crypto/rand"
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

	xA := xdh(&skA, &pkB)
	xB := xdh(&skB, &pkA)

	assert.Equal(t, "shared secret", xA, xB)
}

func TestRepresentativeTransform(t *testing.T) {
	t.Parallel()

	var sk ristretto.Scalar

	sk.Rand()

	pk := sk2pk(&sk)

	rk := pk2rk(&pk)
	if rk == nil {
		t.Skipf("%s has no representative", sk)
	}

	pk2 := rk2pk(rk)

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
		_, _, _, _ = ephemeralKeys(rand.Reader)
	}
}

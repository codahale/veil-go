package kem

import (
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/internal/xdh"
)

func TestExchange(t *testing.T) {
	t.Parallel()

	pkA, skA, err := xdh.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	pkB, skB, err := xdh.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	pkW, secretA, err := Send(skA, pkA, pkB, []byte("boop"), 20)
	if err != nil {
		t.Fatal(err)
	}

	secretB := Receive(skB, pkB, pkA, pkW, []byte("boop"), 20)

	assert.Equal(t, "derived secrets", secretA, secretB)
}

func BenchmarkSend(b *testing.B) {
	pkA, skA, err := xdh.GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	pkB, _, err := xdh.GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = Send(skA, pkA, pkB, []byte("boop"), 20)
	}
}

func BenchmarkReceive(b *testing.B) {
	pkA, skA, err := xdh.GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	pkB, skB, err := xdh.GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	pkW, _, err := Send(skA, pkA, pkB, []byte("boop"), 20)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Receive(skB, pkB, pkA, pkW, []byte("boop"), 20)
	}
}

func BenchmarkKDF(b *testing.B) {
	buf := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		kdf(buf, buf, buf, buf, buf, buf, 64)
	}
}

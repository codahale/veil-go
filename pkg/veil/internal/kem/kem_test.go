package kem

import (
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal/r255"
)

func TestExchange(t *testing.T) {
	t.Parallel()

	privA, pubA, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	privB, pubB, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	pkW, secretA, err := Send(privA, pubA, pubB, 20, true)
	if err != nil {
		t.Fatal(err)
	}

	secretB := Receive(privB, pubB, pubA, pkW, 20, true)

	assert.Equal(t, "derived secrets", secretA, secretB)
}

func BenchmarkSend(b *testing.B) {
	privA, pubA, err := r255.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	_, pubB, err := r255.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = Send(privA, pubA, pubB, 20, false)
	}
}

func BenchmarkReceive(b *testing.B) {
	privA, pubA, err := r255.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	privB, pubB, err := r255.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	pkW, _, err := Send(privA, pubA, pubB, 20, false)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = Receive(privB, pubB, pubA, pkW, 20, false)
	}
}

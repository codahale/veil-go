package kem

import (
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/internal/r255"
)

func TestExchange(t *testing.T) {
	t.Parallel()

	skA, err := r255.NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	privA, pubA := skA.PrivateKey("kem"), skA.PublicKey("kem")

	skB, err := r255.NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	privB, pubB := skB.PrivateKey("kem"), skB.PublicKey("kem")

	pkW, secretA, err := Send(privA, pubA, pubB, []byte("boop"), 20)
	if err != nil {
		t.Fatal(err)
	}

	secretB := Receive(privB, pubB, pubA, pkW, []byte("boop"), 20)

	assert.Equal(t, "derived secrets", secretA, secretB)
}

func BenchmarkSend(b *testing.B) {
	skA, err := r255.NewSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	privA, pubA := skA.PrivateKey("kem"), skA.PublicKey("kem")

	skB, err := r255.NewSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	pubB := skB.PublicKey("kem")
	info := []byte("boop")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = Send(privA, pubA, pubB, info, 20)
	}
}

func BenchmarkReceive(b *testing.B) {
	skA, err := r255.NewSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	privA, pubA := skA.PrivateKey("kem"), skA.PublicKey("kem")

	skB, err := r255.NewSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	privB, pubB := skB.PrivateKey("kem"), skB.PublicKey("kem")

	info := []byte("boop")

	pkW, _, err := Send(privA, pubA, pubB, info, 20)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = Receive(privB, pubB, pubA, pkW, info, 20)
	}
}

func BenchmarkKDF(b *testing.B) {
	zzE := make([]byte, r255.PublicKeySize)
	zzS := make([]byte, r255.PublicKeySize)

	_, pubE, err := r255.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	pubR := pubE.Derive("one")
	pubS := pubE.Derive("two")

	info := []byte("boop")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = kdf(zzE, zzS, pubE, pubR, pubS, info, 20)
	}
}

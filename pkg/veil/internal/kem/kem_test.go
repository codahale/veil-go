package kem

import (
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal/dxof"
	"github.com/codahale/veil/pkg/veil/internal/r255"
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

	pkW, secretA, err := Send(privA, pubA, pubB, testKDF, 20)
	if err != nil {
		t.Fatal(err)
	}

	secretB := Receive(privB, pubB, pubA, pkW, testKDF, 20)

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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = Send(privA, pubA, pubB, testKDF, 20)
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

	pkW, _, err := Send(privA, pubA, pubB, testKDF, 20)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = Receive(privB, pubB, pubA, pkW, testKDF, 20)
	}
}

func testKDF(secret, salt []byte) io.Reader {
	return dxof.MessageKEM(secret, salt)
}

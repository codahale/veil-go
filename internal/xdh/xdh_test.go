package xdh

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSharedSecret(t *testing.T) {
	t.Parallel()

	pkA, skA, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	pkB, skB, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	xA := SharedSecret(skA, pkB)
	xB := SharedSecret(skB, pkA)

	assert.Equal(t, "shared secret", xA, xB)
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	message := []byte("ok bud")

	pk, sk, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(sk, message)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pk, message, sig) {
		t.Error("didn't verify")
	}

	if Verify(pk, []byte("other message"), sig) {
		t.Error("did verify")
	}
}

func BenchmarkGenerateKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = GenerateKeys()
	}
}

func BenchmarkPublicKey(b *testing.B) {
	_, sk, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		PublicKey(sk)
	}
}

func BenchmarkSharedSecret(b *testing.B) {
	_, skA, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	pkB, _, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		SharedSecret(skA, pkB)
	}
}

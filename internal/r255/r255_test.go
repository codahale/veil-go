package r255

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestDiffieHellman(t *testing.T) {
	t.Parallel()

	skA, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	skB, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	xA, err := DiffieHellman(skA, PublicKey(skB))
	if err != nil {
		t.Fatal(err)
	}

	xB, err := DiffieHellman(skB, PublicKey(skA))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "shared secret", xA, xB)
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	message := []byte("ok bud")

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(sk, message)
	if err != nil {
		t.Fatal(err)
	}

	if Verify(PublicKey(sk), []byte("other message"), sig) {
		t.Error("did verify")
	}

	sk2, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	if Verify(PublicKey(sk2), message, sig) {
		t.Error("didn't verify")
	}

	if Verify(PublicKey(sk), []byte("other message"), sig) {
		t.Error("did verify")
	}
}

func BenchmarkNewSecretKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewSecretKey()
	}
}

func BenchmarkPublicKey(b *testing.B) {
	sk, err := NewSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		PublicKey(sk)
	}
}

func BenchmarkSharedSecret(b *testing.B) {
	skA, err := NewSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	skB, err := NewSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	pkB := PublicKey(skB)

	for i := 0; i < b.N; i++ {
		_, _ = DiffieHellman(skA, pkB)
	}
}

package r255

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestDiffieHellman(t *testing.T) {
	t.Parallel()

	skA, pkA, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	skB, pkB, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	xA := DiffieHellman(skA, pkB)
	xB := DiffieHellman(skB, pkA)

	assert.Equal(t, "shared secret", xA, xB)
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	message := []byte("ok bud")

	sk, pk, err := GenerateKeys()
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
	sk, _, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		PublicKey(sk)
	}
}

func BenchmarkSharedSecret(b *testing.B) {
	skA, _, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	_, pkB, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		DiffieHellman(skA, pkB)
	}
}

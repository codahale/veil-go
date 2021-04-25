package schnorr

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Write a message to a signer.
	signer := NewSigner()
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Sign it.
	sig, err := signer.Sign(d, q)
	if err != nil {
		t.Fatal(err)
	}

	// Write a message to a verifier.
	verifier := NewVerifier()
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if !verifier.Verify(q, sig) {
		t.Error("didn't verify")
	}
}

func TestSignAndVerify_BadPublicKey(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Create a fake public key.
	qP := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Write a message to a signer.
	signer := NewSigner()
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Sign it.
	sig, err := signer.Sign(d, q)
	if err != nil {
		t.Fatal(err)
	}

	// Write a message to a verifier.
	verifier := NewVerifier()
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(qP, sig) {
		t.Error("didn't verify")
	}
}

func TestSignAndVerify_BadMessage(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Write a message to a signer.
	signer := NewSigner()
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Sign it.
	sig, err := signer.Sign(d, q)
	if err != nil {
		t.Fatal(err)
	}

	// Write a different message to a verifier.
	verifier := NewVerifier()
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is not great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(q, sig) {
		t.Error("did verify")
	}
}

func TestSignAndVerify_BadSig(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Write a message to a signer.
	signer := NewSigner()
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Sign it.
	sig, err := signer.Sign(d, q)
	if err != nil {
		t.Fatal(err)
	}

	// Modify the signature.
	sig[0] ^= 1

	// Write a message to a verifier.
	verifier := NewVerifier()
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(q, sig) {
		t.Error("did verify")
	}
}

func BenchmarkSigner(b *testing.B) {
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))
	q := ristretto255.NewElement().ScalarBaseMult(d)
	message := make([]byte, 1024)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		signer := NewSigner()
		_, _ = signer.Write(message)
		_, _ = signer.Sign(d, q)
	}
}

func BenchmarkVerifier(b *testing.B) {
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))
	q := ristretto255.NewElement().ScalarBaseMult(d)
	message := make([]byte, 1024)
	signer := NewSigner()
	_, _ = signer.Write(message)

	sig, err := signer.Sign(d, q)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		verifier := NewVerifier()
		_, _ = verifier.Write(message)

		if !verifier.Verify(q, sig) {
			b.Fatal("should have verified")
		}
	}
}

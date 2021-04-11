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
	signer := NewSigner([]byte("associated data"))
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Write a message to a verifier.
	verifier := NewVerifier([]byte("associated data"))
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if !verifier.Verify(q, signer.Sign(d, q)) {
		t.Error("didn't verify")
	}
}

func TestSignAndVerify_BadKey(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Create a fake public key.
	qP := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Write a message to a signer.
	signer := NewSigner(nil)
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Write a message to a verifier.
	verifier := NewVerifier(nil)
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(qP, signer.Sign(d, q)) {
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
	signer := NewSigner(nil)
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Write a different message to a verifier.
	verifier := NewVerifier(nil)
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is not great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(q, signer.Sign(d, q)) {
		t.Error("did verify")
	}
}

func TestSignAndVerify_BadAssociatedData(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Write a message to a signer.
	signer := NewSigner([]byte("one"))
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Write a message to a verifier.
	verifier := NewVerifier([]byte("two"))
	if _, err := io.Copy(verifier, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(q, signer.Sign(d, q)) {
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
	signer := NewSigner(nil)
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Create a signature.
	sig := signer.Sign(d, q)

	// Modify the signature.
	sig[0] ^= 1

	// Write a message to a verifier.
	verifier := NewVerifier(nil)
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
		signer := NewSigner(nil)
		_, _ = signer.Write(message)
		_ = signer.Sign(d, q)
	}
}

func BenchmarkVerifier(b *testing.B) {
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, internal.UniformBytestringSize))
	q := ristretto255.NewElement().ScalarBaseMult(d)
	message := make([]byte, 1024)
	signer := NewSigner(nil)
	_, _ = signer.Write(message)
	sig := signer.Sign(d, q)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		verifier := NewVerifier(nil)
		_, _ = verifier.Write(message)

		if !verifier.Verify(q, sig) {
			b.Fatal("should have verified")
		}
	}
}

type fakeReader struct{}

func (f *fakeReader) Read(p []byte) (n int, err error) {
	return len(p), nil
}

var _ io.Reader = &fakeReader{}

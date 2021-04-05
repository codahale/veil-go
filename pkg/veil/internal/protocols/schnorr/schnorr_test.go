package schnorr

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, r255.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Write a message through a signer.
	signer := NewSigner(io.Discard)
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Read a message through a verifier.
	verifier := NewVerifier(bytes.NewBufferString("this is great"))
	if _, err := io.Copy(io.Discard, verifier); err != nil {
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
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, r255.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Create a fake public key.
	qP := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf2}, r255.UniformBytestringSize))

	// Write a message through a signer.
	signer := NewSigner(io.Discard)
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Read a message through a verifier.
	verifier := NewVerifier(bytes.NewBufferString("this is great"))
	if _, err := io.Copy(io.Discard, verifier); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(qP, signer.Sign(d, q)) {
		t.Error("didn verify")
	}
}

func TestSignAndVerify_BadMessage(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, r255.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Write a message through a signer.
	signer := NewSigner(io.Discard)
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Read a different message through a verifier.
	verifier := NewVerifier(bytes.NewBufferString("this is not great"))
	if _, err := io.Copy(io.Discard, verifier); err != nil {
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
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0xf2}, r255.UniformBytestringSize))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	// Write a message through a signer.
	signer := NewSigner(io.Discard)
	if _, err := io.Copy(signer, bytes.NewBufferString("this is great")); err != nil {
		t.Fatal(err)
	}

	// Create a signature.
	sig := signer.Sign(d, q)

	// Modify the signature.
	sig[0] ^= 1

	// Read a message through a verifier.
	verifier := NewVerifier(bytes.NewBufferString("this is great"))
	if _, err := io.Copy(io.Discard, verifier); err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	if verifier.Verify(q, sig) {
		t.Error("did verify")
	}
}

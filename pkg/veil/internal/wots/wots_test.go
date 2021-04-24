package wots

import (
	"io"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	signer, err := NewSigner(io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("this is ok")

	_, _ = signer.Write(message)
	sig := signer.Sign()

	verifier := NewVerifier(signer.PublicKey)
	_, _ = verifier.Write(message)

	if !verifier.Verify(sig) {
		t.Fatal("should have verified")
	}
}

func TestBadMessage(t *testing.T) {
	t.Parallel()

	signer, err := NewSigner(io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("this is ok")
	_, _ = signer.Write(message)
	verifier := NewVerifier(signer.PublicKey)
	_, _ = verifier.Write([]byte("this is something else"))

	if verifier.Verify(signer.Sign()) {
		t.Fatal("should not have verified")
	}
}

func TestBadPublicKey(t *testing.T) {
	t.Parallel()

	signer, err := NewSigner(io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("this is ok")
	_, _ = signer.Write(message)
	verifier := NewVerifier(make([]byte, 32))
	_, _ = verifier.Write(message)

	if verifier.Verify(signer.Sign()) {
		t.Fatal("should not have verified")
	}
}

func TestBadSig(t *testing.T) {
	t.Parallel()

	signer, err := NewSigner(io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("this is ok")

	_, _ = signer.Write(message)
	sig := signer.Sign()
	sig[32] ^= 1

	verifier := NewVerifier(signer.PublicKey)
	_, _ = verifier.Write(message)

	if verifier.Verify(sig) {
		t.Fatal("should not have verified")
	}
}

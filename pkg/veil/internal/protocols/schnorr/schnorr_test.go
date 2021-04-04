package schnorr

import (
	"bytes"
	"testing"

	"github.com/gtank/ristretto255"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	// Create a fake private key.
	d := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{1, 2}, 32))

	// Calculate the public key.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	sigA, sigB := Sign(d, q, []byte("ok"))

	if !Verify(q, sigA, sigB, []byte("ok")) {
		t.Error("did not verify")
	}

	if Verify(q, sigA, sigB, []byte("not ok")) {
		t.Error("did verify")
	}
}

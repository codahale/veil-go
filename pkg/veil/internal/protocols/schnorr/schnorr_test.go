package schnorr

import (
	"bytes"
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

	sig := Sign(d, q, []byte("ok"))

	if !Verify(q, sig, []byte("ok")) {
		t.Error("did not verify")
	}

	if Verify(q, sig, []byte("not ok")) {
		t.Error("did verify")
	}
}

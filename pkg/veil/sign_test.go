package veil

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSignAndVerifyDetached(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("ok there bud")

	sig, err := sk.PrivateKey("example").SignDetached(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}

	if err := sk.PublicKey("example").VerifyDetached(bytes.NewReader(message), sig); err != nil {
		t.Fatal(err)
	}
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("ok there bud")
	signed := bytes.NewBuffer(nil)
	verified := bytes.NewBuffer(nil)

	sn, err := sk.PrivateKey("example").Sign(signed, bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "bytes written", int64(76), sn)

	vn, err := sk.PublicKey("example").Verify(verified, signed)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "bytes read", int64(12), vn)
	assert.Equal(t, "message", "ok there bud", verified.String())
}

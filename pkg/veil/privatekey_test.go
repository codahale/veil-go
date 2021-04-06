package veil

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPrivateKey_Derive(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abcd := s.PrivateKey("/a/b/c/d")
	abcdP := s.PrivateKey("/a/b").Derive("/c/d")

	assert.Equal(t, "derived key", abcd.PublicKey().String(), abcdP.PublicKey().String())
}

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

func TestEncryptAndDecrypt(t *testing.T) {
	t.Parallel()

	a, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")
	enc := bytes.NewBuffer(nil)
	dec := bytes.NewBuffer(nil)
	publicKeys := []*PublicKey{a.PublicKey("b"), b.PublicKey("a")}

	eb, err := a.PrivateKey("b").Encrypt(enc, bytes.NewReader(message), publicKeys, 1234)
	if err != nil {
		t.Fatal(err)
	}

	pk, db, err := b.PrivateKey("a").Decrypt(dec, enc, publicKeys)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "public key", pk.String(), a.PublicKey("b").String())
	assert.Equal(t, "plaintext", message, dec.Bytes())
	assert.Equal(t, "encrypted bytes", int64(304+1234), eb)
	assert.Equal(t, "decrypted bytes", int64(40), db)
}

func TestFuzzEncryptAndDecrypt(t *testing.T) {
	t.Parallel()

	a, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	enc := io.LimitReader(rand.Reader, 64*1024)
	dec := bytes.NewBuffer(nil)

	_, _, err = a.PrivateKey("two").Decrypt(dec, enc, []*PublicKey{a.PublicKey("two")})
	if err == nil {
		t.Fatal("shouldn't have decrypted")
	}
}

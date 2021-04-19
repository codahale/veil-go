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

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("ok there bud")

	sig, err := sk.PrivateKey("example").Sign(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}

	if err := sk.PublicKey("example").Verify(bytes.NewReader(message), sig); err != nil {
		t.Fatal(err)
	}
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

	eb, err := a.PrivateKey("b").Encrypt(enc, bytes.NewReader(message), publicKeys, 0, 1234)
	if err != nil {
		t.Fatal(err)
	}

	db, err := b.PrivateKey("a").Decrypt(dec, bytes.NewReader(enc.Bytes()), a.PublicKey("b"))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "plaintext", message, dec.Bytes())
	assert.Equal(t, "encrypted bytes", int64(enc.Len()), eb)
	assert.Equal(t, "decrypted bytes", int64(dec.Len()), db)
}

func TestFuzzEncryptAndDecrypt(t *testing.T) {
	t.Parallel()

	a, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 1024*1024)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}

	_, err = a.PrivateKey("two").Decrypt(io.Discard, bytes.NewReader(b), a.PublicKey("two"))
	if err == nil {
		t.Fatal("shouldn't have decrypted")
	}
}

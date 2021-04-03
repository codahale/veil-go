package stream

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := New(key, ad, 4, 16)
	c1 := enc.Encrypt(b1, false)
	c2 := enc.Encrypt(b2, true)

	dec := New(key, ad, 4, 16)

	p1, err := dec.Decrypt(c1, false)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := dec.Decrypt(c2, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "block 1", b1, p1)
	assert.Equal(t, "block 2", b2, p2)
}

func TestKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := New(key, ad, 4, 16)
	c1 := enc.Encrypt(b1, false)
	_ = enc.Encrypt(b2, true)

	dec := New([]byte("not it, chief"), ad, 4, 16)
	if _, err := dec.Decrypt(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestAssociatedDataMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := New(key, ad, 4, 16)
	c1 := enc.Encrypt(b1, false)
	_ = enc.Encrypt(b2, true)

	dec := New(key, []byte("whoops"), 4, 16)
	if _, err := dec.Decrypt(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := New(key, ad, 4, 16)
	c1 := enc.Encrypt(b1, false)
	_ = enc.Encrypt(b2, true)

	c1[0] ^= 1

	dec := New(key, ad, 4, 16)
	if _, err := dec.Decrypt(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := New(key, ad, 4, 16)
	c1 := enc.Encrypt(b1, false)
	_ = enc.Encrypt(b2, true)

	c1[len(c1)-1] ^= 1

	dec := New(key, ad, 4, 16)
	if _, err := dec.Decrypt(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

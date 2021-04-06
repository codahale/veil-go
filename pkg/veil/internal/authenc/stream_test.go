package authenc

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestStreamRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := NewStreamSealer(key, ad, 4, 16)
	c1 := enc.Seal(b1, false)
	c2 := enc.Seal(b2, true)

	dec := NewStreamOpener(key, ad, 4, 16)

	p1, err := dec.Open(c1, false)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := dec.Open(c2, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "block 1", b1, p1)
	assert.Equal(t, "block 2", b2, p2)
}

func TestStreamKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := NewStreamSealer(key, ad, 4, 16)
	c1 := enc.Seal(b1, false)
	_ = enc.Seal(b2, true)

	dec := NewStreamOpener([]byte("not it, chief"), ad, 4, 16)
	if _, err := dec.Open(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestStreamAssociatedDataMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := NewStreamSealer(key, ad, 4, 16)
	c1 := enc.Seal(b1, false)
	_ = enc.Seal(b2, true)

	dec := NewStreamOpener(key, []byte("whoops"), 4, 16)
	if _, err := dec.Open(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestStreamCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := NewStreamSealer(key, ad, 4, 16)
	c1 := enc.Seal(b1, false)
	_ = enc.Seal(b2, true)

	c1[0] ^= 1

	dec := NewStreamOpener(key, ad, 4, 16)
	if _, err := dec.Open(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestStreamTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	ad := []byte("ok then")
	b1 := []byte("woot")
	b2 := []byte("good")

	enc := NewStreamSealer(key, ad, 4, 16)
	c1 := enc.Seal(b1, false)
	_ = enc.Seal(b2, true)

	c1[len(c1)-1] ^= 1

	dec := NewStreamOpener(key, ad, 4, 16)
	if _, err := dec.Open(c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}
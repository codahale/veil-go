package stream

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestStreamRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	b1 := bytes.Repeat([]byte{0xff}, BlockSize)
	b2 := bytes.Repeat([]byte{0xf0}, BlockSize)

	enc := NewSealer(key, nil)
	c1 := enc.Seal(nil, b1, false)
	c2 := enc.Seal(nil, b2, true)

	dec := NewOpener(key, nil)

	p1, err := dec.Open(nil, c1, false)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := dec.Open(nil, c2, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "block 1", b1, p1)
	assert.Equal(t, "block 2", b2, p2)
}

func TestStreamFinalizationMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	b1 := bytes.Repeat([]byte{0xff}, BlockSize)

	enc := NewSealer(key, nil)
	c1 := enc.Seal(nil, b1, true)

	dec := NewOpener(key, nil)
	if _, err := dec.Open(nil, c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestStreamKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	b1 := bytes.Repeat([]byte{0xff}, BlockSize)

	enc := NewSealer(key, nil)
	c1 := enc.Seal(nil, b1, false)

	dec := NewOpener([]byte("not it, chief"), nil)
	if _, err := dec.Open(nil, c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestStreamADMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	b1 := bytes.Repeat([]byte{0xff}, BlockSize)

	enc := NewSealer(key, []byte("one"))
	c1 := enc.Seal(nil, b1, false)

	dec := NewOpener(key, []byte("two"))
	if _, err := dec.Open(nil, c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestStreamCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	b1 := bytes.Repeat([]byte{0xff}, BlockSize)

	enc := NewSealer(key, nil)
	c1 := enc.Seal(nil, b1, false)

	c1[0] ^= 1

	dec := NewOpener(key, nil)
	if _, err := dec.Open(nil, c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestStreamTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is some stuff")
	b1 := bytes.Repeat([]byte{0xff}, BlockSize)

	enc := NewSealer(key, nil)
	c1 := enc.Seal(nil, b1, false)

	c1[len(c1)-1] ^= 1

	dec := NewOpener(key, nil)
	if _, err := dec.Open(nil, c1, false); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func BenchmarkSealer_Seal(b *testing.B) {
	sealer := NewSealer([]byte("ok then"), nil)
	message := []byte("welp welp welp")
	buf := make([]byte, 100)

	for i := 0; i < b.N; i++ {
		_ = sealer.Seal(buf[:0], message, false)
	}
}

func BenchmarkOpener_Open(b *testing.B) {
	sealer := NewSealer([]byte("ok then"), nil)
	ciphertext := sealer.Seal(nil, []byte("welp welp welp"), false)
	buf := make([]byte, len(ciphertext))

	opener := NewOpener([]byte("ok then"), nil)

	for i := 0; i < b.N; i++ {
		_, _ = opener.Open(buf[:0], ciphertext, false)
	}
}

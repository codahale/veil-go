package veil

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestAEAD(t *testing.T) {
	t.Parallel()

	aead := newHMACAEAD(bytes.Repeat([]byte("ayellowsubmarine"), 2))

	assert.Equal(t, "nonce size", 16, aead.NonceSize())
	assert.Equal(t, "overhead", 32, aead.Overhead())

	message := []byte("this is functional")
	iv := []byte("happiness is joy")
	ciphertext := aead.Seal(nil, iv, message, []byte("ok"))
	plaintext, err := aead.Open(nil, iv, ciphertext, []byte("ok"))

	assert.Equal(t, "plaintext", message, plaintext)
	assert.Equal(t, "err", nil, err)
}

func BenchmarkAEAD_Encrypt(b *testing.B) {
	aead := newHMACAEAD(bytes.Repeat([]byte("ayellowsubmarine"), 2))
	nonce := make([]byte, aeadIVSize)
	plaintext := make([]byte, 1024*1024)
	data := make([]byte, 4096)

	for i := 0; i < b.N; i++ {
		aead.Seal(nil, nonce, plaintext, data)
	}
}

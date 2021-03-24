package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestHmacAEAD(t *testing.T) {
	t.Parallel()

	aead := newHMACAEAD([]byte("ayellowsubmarine"))

	assert.Equal(t, "nonce size", 16, aead.NonceSize())
	assert.Equal(t, "overhead", 32, aead.Overhead())

	message := []byte("this is functional")
	iv := []byte("happiness is joy")
	ciphertext := aead.Seal(nil, iv, message, []byte("ok"))
	plaintext, err := aead.Open(nil, iv, ciphertext, []byte("ok"))

	assert.Equal(t, "plaintext", message, plaintext)
	assert.Equal(t, "err", nil, err)
}

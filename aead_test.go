package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestHmacAEAD(t *testing.T) {
	t.Parallel()

	aead := newHMACAEAD([]byte("ayellowsubmarine"))

	assert.Equal(t, "nonce size", 12, aead.NonceSize())
	assert.Equal(t, "overhead", 16+32, aead.Overhead())

	message := []byte("this is functional")
	nonce := []byte("happiness is")
	ciphertext := aead.Seal(nil, nonce, message, []byte("ok"))
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte("ok"))

	assert.Equal(t, "plaintext", message, plaintext)
	assert.Equal(t, "err", nil, err)
}

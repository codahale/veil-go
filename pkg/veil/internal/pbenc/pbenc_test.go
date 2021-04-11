package pbenc

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	passphrase := []byte("this is a secure thing")
	salt := bytes.Repeat([]byte{0x23}, 32)
	message := []byte("this is a real message")

	ciphertext := Encrypt(passphrase, salt, message, 256, 64)

	plaintext, err := Decrypt(passphrase, salt, ciphertext, 256, 64)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "plaintext", message, plaintext)
}

func TestBadPassphrase(t *testing.T) {
	t.Parallel()

	passphrase := []byte("this is a secure thing")
	salt := bytes.Repeat([]byte{0x23}, 32)
	message := []byte("this is a real message")

	ciphertext := Encrypt(passphrase, salt, message, 256, 64)
	if _, err := Decrypt([]byte("boop"), salt, ciphertext, 256, 64); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadSalt(t *testing.T) {
	t.Parallel()

	passphrase := []byte("this is a secure thing")
	salt := bytes.Repeat([]byte{0x23}, 32)
	message := []byte("this is a real message")

	ciphertext := Encrypt(passphrase, salt, message, 256, 64)
	if _, err := Decrypt(passphrase, []byte("boop"), ciphertext, 256, 64); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadSpace(t *testing.T) {
	t.Parallel()

	passphrase := []byte("this is a secure thing")
	salt := bytes.Repeat([]byte{0x23}, 32)
	message := []byte("this is a real message")

	ciphertext := Encrypt(passphrase, salt, message, 256, 64)
	if _, err := Decrypt(passphrase, salt, ciphertext, 128, 64); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadTime(t *testing.T) {
	t.Parallel()

	passphrase := []byte("this is a secure thing")
	salt := bytes.Repeat([]byte{0x23}, 32)
	message := []byte("this is a real message")

	ciphertext := Encrypt(passphrase, salt, message, 256, 64)
	if _, err := Decrypt(passphrase, salt, ciphertext, 256, 32); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	passphrase := []byte("this is a secure thing")
	salt := bytes.Repeat([]byte{0x23}, 32)
	message := []byte("this is a real message")

	for i := 0; i < b.N; i++ {
		_ = Encrypt(passphrase, salt, message, 256, 64)
	}
}

package skenc

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := Encrypt(key, plaintext, 16)

	decrypted, err := Decrypt(key, ciphertext, 16)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted", plaintext, decrypted)
}

func TestKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := Encrypt(key, plaintext, 16)

	if _, err := Decrypt([]byte("ok well no then"), ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := Encrypt(key, plaintext, 16)
	ciphertext[0] ^= 1

	if _, err := Decrypt(key, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := Encrypt(key, plaintext, 16)

	ciphertext[len(ciphertext)-1] ^= 1

	if _, err := Decrypt(key, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	for i := 0; i < b.N; i++ {
		_ = Encrypt(key, plaintext, 16)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := Encrypt(key, plaintext, 16)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = Decrypt(key, ciphertext, 16)
	}
}

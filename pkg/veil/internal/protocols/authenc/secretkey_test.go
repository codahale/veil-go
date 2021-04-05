package authenc

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSecretKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := EncryptSecretKey(key, plaintext, 16)

	decrypted, err := DecryptSecretKey(key, ciphertext, 16)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted", plaintext, decrypted)
}

func TestSecretKeyKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := EncryptSecretKey(key, plaintext, 16)

	if _, err := DecryptSecretKey([]byte("ok well no then"), ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestSecretKeyCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := EncryptSecretKey(key, plaintext, 16)
	ciphertext[0] ^= 1

	if _, err := DecryptSecretKey(key, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestSecretKeyTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := EncryptSecretKey(key, plaintext, 16)

	ciphertext[len(ciphertext)-1] ^= 1

	if _, err := DecryptSecretKey(key, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

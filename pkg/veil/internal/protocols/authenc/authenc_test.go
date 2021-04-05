package authenc

import (
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal/r255"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	_, pubEH, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	decrypted, err := DecryptHeader(key, pubEH, ciphertext, 16)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted", plaintext, decrypted)
}

func TestKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	_, pubEH, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	if _, err := DecryptHeader([]byte("ok well no then"), pubEH, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestPubKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	_, pubEH, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, pubEH2, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	if _, err := DecryptHeader(key, pubEH2, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	_, pubEH, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)
	ciphertext[0] ^= 1

	if _, err := DecryptHeader(key, pubEH, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	_, pubEH, err := r255.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	ciphertext[len(ciphertext)-1] ^= 1

	if _, err := DecryptHeader(key, pubEH, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

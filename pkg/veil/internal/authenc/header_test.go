package authenc

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
)

func TestHeaderRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")
	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	decrypted, err := DecryptHeader(key, pubEH, ciphertext, 16)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted", plaintext, decrypted)
}

func TestHeaderKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")
	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	if _, err := DecryptHeader([]byte("ok well no then"), pubEH, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestHeaderPubKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")
	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	pubEH2 := ristretto255.NewElement().Add(pubEH, pubEH)
	if _, err := DecryptHeader(key, pubEH2, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestHeaderCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)
	ciphertext[0] ^= 1

	if _, err := DecryptHeader(key, pubEH, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestHeaderTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")
	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	ciphertext[len(ciphertext)-1] ^= 1

	if _, err := DecryptHeader(key, pubEH, ciphertext, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func BenchmarkEncryptHeader(b *testing.B) {
	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = EncryptHeader(key, pubEH, plaintext, 16)
	}
}

func BenchmarkDecryptHeader(b *testing.B) {
	key := []byte("this is a good time")
	plaintext := []byte("welcome to the jungle")
	ciphertext := EncryptHeader(key, pubEH, plaintext, 16)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = DecryptHeader(key, pubEH, ciphertext, 16)
	}
}

//nolint:gochecknoglobals // test setup
var pubEH = ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x12}, internal.UniformBytestringSize))

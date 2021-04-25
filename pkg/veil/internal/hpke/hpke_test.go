package hpke

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(nil, dR, qR, qS, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "plaintext", message, plaintext)
}

func TestWrongPrivateKey(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		t.Fatal(err)
	}

	dX := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x69}, internal.UniformBytestringSize))

	if _, err := Decrypt(nil, dX, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestWrongPublicKey(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		t.Fatal(err)
	}

	qX := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x69}, internal.UniformBytestringSize))

	if _, err := Decrypt(nil, dR, qX, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestWrongSenderKey(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		t.Fatal(err)
	}

	qX := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x69}, internal.UniformBytestringSize))

	if _, err := Decrypt(nil, dR, qR, qX, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadEphemeralKey(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext[0] ^= 1

	if _, err := Decrypt(nil, dR, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadCiphertext(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext[internal.ElementSize+5] ^= 1

	if _, err := Decrypt(nil, dR, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadMAC(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext[len(ciphertext)-4] ^= 1

	if _, err := Decrypt(nil, dR, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(nil, dS, qS, qR, message)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	ciphertext, err := Encrypt(nil, dS, qS, qR, message)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, _ = Decrypt(nil, dR, qR, qS, ciphertext)
	}
}

//nolint:gochecknoglobals // constants
var (
	dS = ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x4f}, internal.UniformBytestringSize))
	qS = ristretto255.NewElement().ScalarBaseMult(dS)
	dR = ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x22}, internal.UniformBytestringSize))
	qR = ristretto255.NewElement().ScalarBaseMult(dR)

	message = []byte("hello this is dog")
)

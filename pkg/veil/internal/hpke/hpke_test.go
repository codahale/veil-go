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

	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)

	q, plaintext, err := Decrypt(nil, dR, qR, qS, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "plaintext", message, plaintext)
	assert.Equal(t, "ephemeral public key", qE.String(), q.String())
}

func TestWrongPrivateKey(t *testing.T) {
	t.Parallel()

	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)
	dX := ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x69}, internal.UniformBytestringSize))

	if _, _, err := Decrypt(nil, dX, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestWrongPublicKey(t *testing.T) {
	t.Parallel()

	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)
	qX := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x69}, internal.UniformBytestringSize))

	if _, _, err := Decrypt(nil, dR, qX, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestWrongSenderKey(t *testing.T) {
	t.Parallel()

	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)
	qX := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x69}, internal.UniformBytestringSize))

	if _, _, err := Decrypt(nil, dR, qR, qX, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadEphemeralKey(t *testing.T) {
	t.Parallel()

	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)
	ciphertext[0] ^= 1

	if _, _, err := Decrypt(nil, dR, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadCiphertext(t *testing.T) {
	t.Parallel()

	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)
	ciphertext[internal.ElementSize+5] ^= 1

	if _, _, err := Decrypt(nil, dR, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestBadMAC(t *testing.T) {
	t.Parallel()

	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)
	ciphertext[len(ciphertext)-4] ^= 1

	if _, _, err := Decrypt(nil, dR, qR, qS, ciphertext); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Encrypt(nil, dS, dE, qS, qE, qR, message)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	ciphertext := Encrypt(nil, dS, dE, qS, qE, qR, message)

	for i := 0; i < b.N; i++ {
		_, _, _ = Decrypt(nil, dR, qR, qS, ciphertext)
	}
}

//nolint:gochecknoglobals // constants
var (
	dS = ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x4f}, internal.UniformBytestringSize))
	qS = ristretto255.NewElement().ScalarBaseMult(dS)
	dE = ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x69}, internal.UniformBytestringSize))
	qE = ristretto255.NewElement().ScalarBaseMult(dE)
	dR = ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x22}, internal.UniformBytestringSize))
	qR = ristretto255.NewElement().ScalarBaseMult(dR)

	message = []byte("hello this is dog")
)

package veil

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestRoundTrip(t *testing.T) {
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicC, privateC, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")
	ciphertext, err := Encrypt(rand.Reader, privateB, []ed25519.PublicKey{publicB, publicC}, message, 1024, 40)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(privateC, publicB, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("Plaintext wss %v, expected %v", plaintext, message)
	}

	for i := 0; i < 1000; i++ {
		corruptCiphertext := corrupt(ciphertext)

		_, err = Decrypt(privateC, publicB, corruptCiphertext)
		if err == nil {
			t.Fatalf("Was able to decrypt %v/%v/%v", privateC, publicB, corruptCiphertext)
		}

	}
}

func BenchmarkVeilEncrypt(b *testing.B) {
	r := fakeRand{}

	publicB, privateB, err := ed25519.GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}

	publicC, _, err := ed25519.GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")

	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(r, privateB, []ed25519.PublicKey{publicB, publicC}, message, 1024, 40)
	}
}

func BenchmarkVeilDecrypt(b *testing.B) {
	r := fakeRand{}

	publicB, privateB, err := ed25519.GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}

	publicC, privateC, err := ed25519.GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")
	ciphertext, err := Encrypt(r, privateB, []ed25519.PublicKey{publicB, publicC}, message, 1024, 40)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, _ = Decrypt(privateC, publicB, ciphertext)
	}
}

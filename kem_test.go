package veil

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestKEM(t *testing.T) {
	public, _, private, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := kemEncrypt(rand.Reader, public, []byte("a secret"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := kemDecrypt(private, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if expected, actual := len(plaintext)+kemOverhead, len(ciphertext); expected != actual {
		t.Errorf("Expected ciphertext to be %d bytes, but was %d", expected, actual)
	}

	if expected, actual := []byte("a secret"), plaintext; !bytes.Equal(expected, actual) {
		t.Errorf("Expected %v, but was %v", expected, actual)
	}

	for i := 0; i < 1000; i++ {
		corruptCiphertext := corrupt(ciphertext)
		_, err = kemDecrypt(private, corruptCiphertext)
		if err == nil {
			t.Fatalf("Was able to decrypt %v with %v", corruptCiphertext, private)
		}
	}
}

func TestXDH(t *testing.T) {
	publicA, _, privateA, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicB, _, privateB, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sent := x25519(privateA, publicB)
	received := x25519(privateB, publicA)

	if !bytes.Equal(sent, received) {
		t.Errorf("XDH mismatch: %v/%v", sent, received)
	}
}

func BenchmarkEphemeralKeys(b *testing.B) {
	r := fakeRand{}
	for i := 0; i < b.N; i++ {
		_, _, _, _ = ephemeralKeys(r)
	}
}

func BenchmarkXDH(b *testing.B) {
	publicA, _, _, err := ephemeralKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, _, privateB, err := ephemeralKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_ = x25519(privateB, publicA)
	}
}

func BenchmarkKEMEncrypt(b *testing.B) {
	r := fakeRand{}
	public, _, err := ed25519.GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_, _ = kemEncrypt(r, public, []byte("a secret"))
	}
}

func BenchmarkKEMDecrypt(b *testing.B) {
	r := fakeRand{}
	public, private, err := ed25519.GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}

	ciphertext, err := kemEncrypt(r, public, []byte("a secret"))
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, _ = kemDecrypt(private, ciphertext)
	}
}

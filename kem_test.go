package veil

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestKEM(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := kemEncrypt(public, []byte("a secret"))
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
}

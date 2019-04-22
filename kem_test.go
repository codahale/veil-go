package veil

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKEM(t *testing.T) {
	pkI, _, skI, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkR, _, skR, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := kemEncrypt(rand.Reader, skI, pkI, pkR, []byte("a secret"), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := kemDecrypt(skR, pkR, pkI, ciphertext, []byte("data"))
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
		data := []byte("data")
		corruptCiphertext := corrupt(ciphertext)
		corruptData := corrupt(data)

		_, err = kemDecrypt(skR, pkR, pkI, corruptCiphertext, data)
		if err == nil {
			t.Fatalf("Was able to decrypt %v with %v/%v", corruptCiphertext, skI, data)
		}

		_, err = kemDecrypt(skR, pkR, pkI, ciphertext, corruptData)
		if err == nil {
			t.Fatalf("Was able to decrypt %v with %v/%v", ciphertext, skI, corruptData)
		}
	}
}

func TestXDH(t *testing.T) {
	pkA, _, skA, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkB, _, skB, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sent := x25519(skA, pkB)
	received := x25519(skB, pkA)

	if !bytes.Equal(sent, received) {
		t.Errorf("XDH mismatch: %v/%v", sent, received)
	}
}

func BenchmarkEphemeralKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, _ = ephemeralKeys(rand.Reader)
	}
}

func BenchmarkXDH(b *testing.B) {
	pkA, _, _, err := ephemeralKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, _, skB, err := ephemeralKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_ = x25519(skB, pkA)
	}
}

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

	ciphertext, err := kemEncrypt(rand.Reader, pkI, skI, pkR, []byte("a secret"), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := kemDecrypt(pkR, skR, pkI, ciphertext, []byte("data"))
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

		_, err = kemDecrypt(pkR, skR, pkI, corruptCiphertext, data)
		if err == nil {
			t.Fatalf("Was able to decrypt %v with %v/%v", corruptCiphertext, skI, data)
		}

		_, err = kemDecrypt(pkR, skR, pkI, ciphertext, corruptData)
		if err == nil {
			t.Fatalf("Was able to decrypt %v with %v/%v", ciphertext, skI, corruptData)
		}
	}
}

func BenchmarkEphemeralKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, _ = ephemeralKeys(rand.Reader)
	}
}

package veil

import (
	"crypto/rand"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestKEM(t *testing.T) {
	t.Parallel()

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

	assert.Equal(t, "ciphertext length", len(plaintext)+kemOverhead, len(ciphertext))

	assert.Equal(t, "plaintext", []byte("a secret"), plaintext)
}

func TestKEMCorruption(t *testing.T) {
	t.Parallel()

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

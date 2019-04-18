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

func TestXDH(t *testing.T) {
	ephemeralPublic, ephemeralPrivate, err := ephemeralKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	staticPublic, staticPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sent := xdhSend(ephemeralPrivate, staticPublic)
	received := xdhReceive(staticPrivate, ephemeralPublic)

	if !bytes.Equal(sent, received) {
		t.Errorf("XDH mismatch: %v/%v", sent, received)
	}
}

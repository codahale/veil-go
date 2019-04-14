package veil

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	publicB, _, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	publicC, privateC, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")
	ciphertext, err := Encrypt([]PublicKey{publicB, publicC}, message, 1024, 40)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(privateC, publicC, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("Plaintext wss %v, expected %v", plaintext, message)
	}
}

func TestXDH(t *testing.T) {
	publicA, privateA, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	publicB, privateB, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	secA := sharedSecret(privateA, publicB)
	secB := sharedSecret(privateB, publicA)

	if !bytes.Equal(secA, secB) {
		t.Errorf("XDH mismatch: %v/%v", secA, secB)
	}
}

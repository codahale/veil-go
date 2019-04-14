package veil

import (
	"bytes"
	"testing"
)

func TestDEM(t *testing.T) {
	key := []byte("ayellowsubmarineayellowsubmarine")
	plaintext := []byte("ok this is swell")
	data := []byte("yes, this is great")

	ciphertext, err := demEncrypt(key, plaintext, data)
	if err != nil {
		t.Fatal(err)
	}

	if expected, actual := len(plaintext)+demOverhead, len(ciphertext); expected != actual {
		t.Errorf("Expected ciphertext to be %d bytes, but was %d", expected, actual)
	}

	actual, err := demDecrypt(key, ciphertext, data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, actual) {
		t.Errorf("Expected %v, but was %v", plaintext, actual)
	}
}

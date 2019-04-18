package veil

import (
	"bytes"
	"crypto/rand"
	rand2 "math/rand"
	"testing"
)

func TestDEM(t *testing.T) {
	key := []byte("ayellowsubmarineayellowsubmarine")
	plaintext := []byte("ok this is swell")
	data := []byte("yes, this is great")

	ciphertext, err := demEncrypt(rand.Reader, key, plaintext, data)
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

	for i := 0; i < 1000; i++ {
		corruptKey := corrupt(key)
		corruptCiphertext := corrupt(ciphertext)
		corruptData := corrupt(data)

		_, err := demDecrypt(corruptKey, ciphertext, data)
		if err == nil {
			t.Errorf("Was able to decrypt %v/%v/%v", corruptKey, ciphertext, data)
		}

		_, err = demDecrypt(key, corruptCiphertext, data)
		if err == nil {
			t.Errorf("Was able to decrypt %v/%v/%v", key, corruptCiphertext, data)
		}

		_, err = demDecrypt(key, ciphertext, corruptData)
		if err == nil {
			t.Errorf("Was able to decrypt %v/%v/%v", key, ciphertext, corruptData)
		}
	}
}

func BenchmarkDEMEncrypt(b *testing.B) {
	key := []byte("ayellowsubmarineayellowsubmarine")
	plaintext := []byte("ok this is swell")
	data := []byte("yes, this is great")
	r := fakeRand{}
	for i := 0; i < b.N; i++ {
		_, _ = demEncrypt(r, key, plaintext, data)
	}
}

func BenchmarkDEMDecrypt(b *testing.B) {
	key := []byte("ayellowsubmarineayellowsubmarine")
	plaintext := []byte("ok this is swell")
	data := []byte("yes, this is great")
	r := fakeRand{}
	ciphertext, _ := demEncrypt(r, key, plaintext, data)
	for i := 0; i < b.N; i++ {
		_, _ = demDecrypt(key, ciphertext, data)
	}
}

func BenchmarkDEMDecryptBad(b *testing.B) {
	key := []byte("ayellowsubmarineayellowsubmarine")
	plaintext := []byte("ok this is swell")
	data := []byte("yes, this is great")
	r := fakeRand{}
	ciphertext, _ := demEncrypt(r, key, plaintext, data)
	ciphertext[0] ^= 1
	for i := 0; i < b.N; i++ {
		_, _ = demDecrypt(key, ciphertext, data)
	}
}

type fakeRand struct {
}

func (fakeRand) Read(p []byte) (n int, err error) {
	return len(p), nil
}

func corrupt(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	c[rand2.Intn(len(c))] ^= byte(1 << uint(rand2.Intn(7)))
	if bytes.Equal(b, c) {
		panic("ag")
	}
	return c
}

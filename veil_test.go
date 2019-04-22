package veil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	rand2 "math/rand"
	"testing"
)

func Example() {
	// Alice generates a set of keys and shares her public key with Bob.
	pkA, skA, err := GenerateKeys(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Bob generates a set of keys and shares his public key with Alice.
	pkB, skB, err := GenerateKeys(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice encrypts a message for her and Bob with 10 fake recipients and 1000 bytes of padding.
	message := []byte("one two three four I declare a thumb war")
	ciphertext, err := Encrypt(rand.Reader, skA, pkA, []PublicKey{pkA, pkB}, message, 1000, 10)
	if err != nil {
		panic(err)
	}

	// Bob decrypts the message and sees that it was encrypted by Alice.
	pk, plaintext, err := Decrypt(skB, pkB, []PublicKey{pkB, pkA}, ciphertext)
	if err != nil {
		panic(err)
	}

	if bytes.Equal(pk, pkA) {
		fmt.Println("sent by A")
	} else {
		fmt.Println("sent by B")
	}
	fmt.Println(string(plaintext))
	// Output:
	// sent by A
	// one two three four I declare a thumb war
}

func TestRoundTrip(t *testing.T) {
	pkA, skA, err := GenerateKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkB, skB, err := GenerateKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")
	ciphertext, err := Encrypt(rand.Reader, skA, pkA, []PublicKey{pkA, pkB}, message, 1000, 10)
	if err != nil {
		t.Fatal(err)
	}

	pk, plaintext, err := Decrypt(skB, pkB, []PublicKey{pkB, pkA}, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pk, pkA) {
		t.Errorf("Public key was %v, expected %v", pk, pkA)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("Plaintext wss %v, expected %v", plaintext, message)
	}

	for i := 0; i < 1000; i++ {
		corruptCiphertext := corrupt(ciphertext)

		_, _, err = Decrypt(skB, pkB, []PublicKey{pkA}, corruptCiphertext)
		if err == nil {
			t.Fatalf("Was able to decrypt %v/%v/%v", skB, pkA, corruptCiphertext)
		}

	}
}

func BenchmarkVeilEncrypt(b *testing.B) {
	pkA, skA, err := GenerateKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	pkB, _, err := GenerateKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024*10)

	for i := 0; i < b.N; i++ {
		_, err = Encrypt(rand.Reader, skA, pkA, []PublicKey{pkA, pkB}, message, 1024, 40)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVeilDecrypt(b *testing.B) {
	pkA, skA, err := GenerateKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	pkB, skB, err := GenerateKeys(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024*10)

	ciphertext, err := Encrypt(rand.Reader, skA, pkA, []PublicKey{pkA, pkB}, message, 1024, 40)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, _, err = Decrypt(skB, pkB, []PublicKey{pkA}, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
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

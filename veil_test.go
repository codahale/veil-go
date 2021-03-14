package veil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	rand2 "math/rand"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func Example() {
	// Alice generates a secret key and shares her public key with Bob.
	alice, err := NewSecretKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Bob generates a key pair and shares his public key with Alice.
	bob, err := NewSecretKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice writes a message.
	message := []byte("one two three four I declare a thumb war")

	// Alice encrypts the message for her and Bob with 10 fake recipients and 1000 bytes of padding.
	ciphertext, err := alice.Encrypt(rand.Reader, []*PublicKey{alice.PublicKey(), bob.PublicKey()}, message, 1000, 10)
	if err != nil {
		panic(err)
	}

	// Bob decrypts the message and sees that it was encrypted by Alice.
	pk, plaintext, err := bob.Decrypt([]*PublicKey{bob.PublicKey(), alice.PublicKey()}, ciphertext)
	if err != nil {
		panic(err)
	}

	if bytes.Equal(pk.Bytes(), alice.PublicKey().Bytes()) {
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
	t.Parallel()

	a, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")

	ciphertext, err := a.Encrypt(rand.Reader, []*PublicKey{a.PublicKey(), b.PublicKey()}, message, 1000, 10)
	if err != nil {
		t.Fatal(err)
	}

	pk, plaintext, err := b.Decrypt([]*PublicKey{a.PublicKey(), b.PublicKey()}, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "public key", a.PublicKey().Bytes(), pk.Bytes())

	assert.Equal(t, "plaintext", message, plaintext)

	for i := 0; i < 1000; i++ {
		corruptCiphertext := corrupt(ciphertext)

		_, _, err = b.Decrypt([]*PublicKey{a.PublicKey()}, corruptCiphertext)
		if err == nil {
			t.Fatalf("Was able to decrypt %v#/%#v/%v", a, b, corruptCiphertext)
		}
	}
}

func BenchmarkVeilEncrypt(b *testing.B) {
	alice, err := NewSecretKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	bob, err := NewSecretKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024*10)

	for i := 0; i < b.N; i++ {
		_, err = alice.Encrypt(rand.Reader, []*PublicKey{alice.PublicKey(), bob.PublicKey()}, message, 1024, 40)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVeilDecrypt(b *testing.B) {
	alice, err := NewSecretKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	bob, err := NewSecretKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024*10)

	ciphertext, err := alice.Encrypt(rand.Reader, []*PublicKey{alice.PublicKey(), bob.PublicKey()}, message, 1024, 40)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, _, err = bob.Decrypt([]*PublicKey{alice.PublicKey()}, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func corrupt(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)

	for bytes.Equal(b, c) {
		//nolint:gosec // Don't need cryptographic security for tests.
		c[rand2.Intn(len(c))] ^= byte(1 << uint(rand2.Intn(7)))
	}

	return c
}

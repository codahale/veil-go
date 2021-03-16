package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	rand2 "math/rand"
	"testing"

	"github.com/bwesterb/go-ristretto"
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

	if alice.PublicKey().Equals(pk) {
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

	assert.Equal(t, "public key", pk.q.Bytes(), a.q.Bytes())

	assert.Equal(t, "plaintext", message, plaintext)

	for i := 0; i < 1000; i++ {
		corruptCiphertext := corrupt(ciphertext)

		_, _, err = b.Decrypt([]*PublicKey{a.PublicKey()}, corruptCiphertext)
		if err == nil {
			t.Fatalf("Was able to decrypt %v#/%#v/%v", a, b, corruptCiphertext)
		}
	}
}

func TestPublicKey_Text(t *testing.T) {
	t.Parallel()

	var s ristretto.Scalar

	// Generate a constant secret key.
	s.Derive([]byte("this is a secret key"))

	// Derive the public key.
	q := sk2pk(&s)

	// Create a constant public key.
	pk := &PublicKey{q: *q}

	j, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "text representation", `"2CDombiqQi23aJon7RnfMYwk-YbHQabdCMVAJA2k2w8"`, string(j))

	var pk2 PublicKey
	if err := json.Unmarshal(j, &pk2); err != nil {
		t.Fatal(err)
	}

	if !pk.q.Equals(&pk2.q) {
		t.Error("bad round trip")
	}
}

func TestPublicKey_Binary(t *testing.T) {
	t.Parallel()

	var s ristretto.Scalar

	// Generate a constant secret key.
	s.Derive([]byte("this is a secret key"))

	// Derive the public key.
	q := sk2pk(&s)

	// Create a constant public key.
	pk := &PublicKey{q: *q}

	w := bytes.NewBuffer(nil)
	e := gob.NewEncoder(w)

	if err := e.Encode(pk); err != nil {
		t.Fatal(err)
	}

	var pk2 PublicKey

	r := bytes.NewReader(w.Bytes())
	d := gob.NewDecoder(r)

	if err := d.Decode(&pk2); err != nil {
		t.Fatal(err)
	}

	if !pk.q.Equals(&pk2.q) {
		t.Error("bad round trip")
	}
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation", sk.PublicKey().String(), sk.String())
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

package veil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/internal/r255"
)

func Example() {
	// Alice generates a secret key.
	alice, err := NewSecretKey()
	if err != nil {
		panic(err)
	}

	// Alice derives a public key with the path "/friends/bob" and shares it with Bob.
	alicePub := alice.PublicKey("/friends/bob")

	// Bob generates a secret key.
	bob, err := NewSecretKey()
	if err != nil {
		panic(err)
	}

	// Bob derives a public key with the label "/friends/alice" and shares it with Alice.
	bobPub := bob.PublicKey("/friends/alice")

	// Alice writes a message.
	message := bytes.NewReader([]byte("one two three four I declare a thumb war"))
	encrypted := bytes.NewBuffer(nil)

	// Alice creates a list of recipients -- her and Bob -- but adds 98 fake recipients so Bob won't
	// know the true number of recipients.
	recipients, err := AddFakes([]*PublicKey{alicePub, bobPub}, 98)
	if err != nil {
		panic(err)
	}

	// Alice encrypts the message for her, Bob, and the 98 fakes, adding random padding to disguise
	// its true length. She uses the path "/friends/bob" to create the message because it
	// corresponds with the public key she sent Bob.
	_, err = alice.Encrypt(encrypted, message, recipients, "/friends/bob", 4829)
	if err != nil {
		panic(err)
	}

	// Alice sends the message to Bob.
	received := bytes.NewReader(encrypted.Bytes())
	decrypted := bytes.NewBuffer(nil)

	// Bob decrypts the message. He uses the path "/friends/alice" because it corresponds with the
	// public key he sent Alice.
	pk, _, err := bob.Decrypt(decrypted, received, []*PublicKey{bobPub, alicePub}, "/friends/alice")
	if err != nil {
		panic(err)
	}

	// Bob checks that the sender of the message was indeed Alice.
	if pk.String() == alicePub.String() {
		fmt.Println("sent by A")
	} else {
		fmt.Println("sent by B")
	}

	// Bob views the decrypted message.
	fmt.Println(decrypted.String())
	// Output:
	// sent by A
	// one two three four I declare a thumb war
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	a, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")
	enc := bytes.NewBuffer(nil)
	dec := bytes.NewBuffer(nil)
	publicKeys := []*PublicKey{a.PublicKey("b"), b.PublicKey("a")}

	eb, err := a.Encrypt(enc, bytes.NewReader(message), publicKeys, "b", 1234)
	if err != nil {
		t.Fatal(err)
	}

	pk, db, err := b.Decrypt(dec, enc, publicKeys, "a")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "public key", pk.String(), a.PublicKey("b").String())
	assert.Equal(t, "plaintext", message, dec.Bytes())
	assert.Equal(t, "encrypted bytes", int64(304+1234), eb)
	assert.Equal(t, "decrypted bytes", int64(40), db)
}

func TestFuzz(t *testing.T) {
	t.Parallel()

	a, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	enc := io.LimitReader(rand.Reader, 64*1024)
	dec := bytes.NewBuffer(nil)

	_, _, err = a.Decrypt(dec, enc, []*PublicKey{a.PublicKey("two")}, "two")
	if err == nil {
		t.Fatal("shouldn't have decrypted")
	}
}

func TestSecretKey_PublicKey(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abc := s.k.PublicKey("/").Derive("a").Derive("b").Derive("c")
	abcP := s.PublicKey("/a/b/c").k

	assert.Equal(t, "derived key", abc.String(), abcP.String())
}

func TestPublicKey_Derive(t *testing.T) {
	t.Parallel()

	s, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	abcd := s.PublicKey("/a/b/c/d").k
	abcdP := s.PublicKey("/a/b").Derive("/c/d").k

	assert.Equal(t, "derived key", abcd.String(), abcdP.String())
}

func TestPublicKey_UnmarshalText(t *testing.T) {
	t.Parallel()

	base32 := "ZJ756O23HCIC455GWQU24GJI3JHZGGYYZH3HDBWHGHQH3ZNTJMCQ"

	var in PublicKey
	if err := in.UnmarshalText([]byte(base32)); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "round trip", base32, in.String())
}

func TestPublicKey_MarshalText(t *testing.T) {
	t.Parallel()

	want := []byte("ZJ756O23HCIC455GWQU24GJI3JHZGGYYZH3HDBWHGHQH3ZNTJMCQ")

	var in PublicKey
	if err := in.UnmarshalText(want); err != nil {
		t.Fatal(err)
	}

	got, err := in.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "round trip", want, got)
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	k, err := r255.DecodeSecretKey([]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine"))
	if err != nil {
		t.Fatal(err)
	}

	sk := &SecretKey{
		k: k,
	}

	assert.Equal(t, "string representation", "a8355e9a483935fa", sk.String())
}

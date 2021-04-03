package veil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func Example() {
	// Alice generates a secret key.
	alice, err := NewSecretKey()
	if err != nil {
		panic(err)
	}

	// Alice derives a private key with the ID "/friends/bea", generates a public key from that, and
	// shares the public key with Bea.
	aliceBeaPriv := alice.PrivateKey("/friends/bea")
	aliceBeaPub := aliceBeaPriv.PublicKey()

	// Bea generates a secret key.
	bea, err := NewSecretKey()
	if err != nil {
		panic(err)
	}

	// Bea derives a private key with the ID "/friends/alice", generates a public key from that, and
	// shares the public key with Alice.
	beaAlicePriv := bea.PrivateKey("/friends/alice")
	beaAlicePub := beaAlicePriv.PublicKey()

	// Alice writes a message.
	message := bytes.NewReader([]byte("one two three four I declare a thumb war"))
	encrypted := bytes.NewBuffer(nil)

	// Alice creates a list of recipients -- her and Bea -- but adds 98 fake recipients so Bea won't
	// know the true number of recipients.
	recipients, err := AddFakes([]*PublicKey{aliceBeaPub, beaAlicePub}, 98)
	if err != nil {
		panic(err)
	}

	// Alice encrypts the message for her, Bea, and the 98 fakes, adding random padding to disguise
	// its true length. She uses the "/friends/bea" private key to encrypt the message because it
	// corresponds with the public key she sent Bea.
	_, err = aliceBeaPriv.Encrypt(encrypted, message, recipients, 4829)
	if err != nil {
		panic(err)
	}

	// Alice sends the message to Bea.
	received := bytes.NewReader(encrypted.Bytes())
	decrypted := bytes.NewBuffer(nil)

	// Bea decrypts the message. She uses the "/friends/alice" private key because it corresponds
	// with the public key she sent Alice.
	pk, _, err := beaAlicePriv.Decrypt(decrypted, received, []*PublicKey{beaAlicePub, aliceBeaPub})
	if err != nil {
		panic(err)
	}

	// Bea checks that the sender of the message was indeed Alice.
	if pk.String() == aliceBeaPub.String() {
		fmt.Println("sent by A")
	} else {
		fmt.Println("sent by B")
	}

	// Bea views the decrypted message.
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

	eb, err := a.PrivateKey("b").Encrypt(enc, bytes.NewReader(message), publicKeys, 1234)
	if err != nil {
		t.Fatal(err)
	}

	pk, db, err := b.PrivateKey("a").Decrypt(dec, enc, publicKeys)
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

	_, _, err = a.PrivateKey("two").Decrypt(dec, enc, []*PublicKey{a.PublicKey("two")})
	if err == nil {
		t.Fatal("shouldn't have decrypted")
	}
}

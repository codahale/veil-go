package veil

import (
	"bytes"
	"fmt"
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
	_, err = beaAlicePriv.Decrypt(decrypted, received, aliceBeaPub)
	if err != nil {
		panic(err)
	}

	// Bea views the decrypted message.
	fmt.Println(decrypted.String())
	// Output:
	// one two three four I declare a thumb war
}

func TestAddFakes(t *testing.T) {
	t.Parallel()

	alice, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	bea, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	all, err := AddFakes([]*PublicKey{alice.PublicKey("one"), bea.PublicKey("one")}, 20)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "total count", 22, len(all))

	alices, beas, others := 0, 0, 0

	for _, pk := range all {
		switch pk.String() {
		case alice.PublicKey("one").String():
			alices++
		case bea.PublicKey("one").String():
			beas++
		default:
			others++
		}
	}

	assert.Equal(t, "alice count", 1, alices)
	assert.Equal(t, "bea count", 1, beas)
	assert.Equal(t, "other count", 20, others)
}

package veil

import (
	"bytes"
	"fmt"
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

	// Alice encrypts the message for herself, Bea, and 98 fake recipients, adding random padding to
	// disguise its true length. She uses the "/friends/bea" private key to encrypt the message
	// because it corresponds with the public key she sent Bea.
	_, err = aliceBeaPriv.Encrypt(encrypted, message, []*PublicKey{aliceBeaPub, beaAlicePub}, 98, 4829)
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

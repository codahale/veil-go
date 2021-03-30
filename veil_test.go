package veil

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func Example() {
	// Alice generates a secret key and shares her public key with Bob.
	alice, err := NewSecretKey()
	if err != nil {
		panic(err)
	}

	// Bob generates a key pair and shares his public key with Alice.
	bob, err := NewSecretKey()
	if err != nil {
		panic(err)
	}

	// Alice writes a message.
	message := bytes.NewReader([]byte("one two three four I declare a thumb war"))
	encrypted := bytes.NewBuffer(nil)

	// Alice creates a list of recipients -- her and Bob -- but adds 98 fake recipients so Bob won't
	// know the true number of recipients.
	recipients, err := AddFakes([]PublicKey{alice.PublicKey(), bob.PublicKey()}, 98)
	if err != nil {
		panic(err)
	}

	// Alice encrypts the message for her, Bob, and the 98 fakes, adding random padding to disguise
	// its true length.
	_, err = alice.Encrypt(encrypted, message, recipients, 4829)
	if err != nil {
		panic(err)
	}

	// Alice sends the message to Bob.
	received := bytes.NewReader(encrypted.Bytes())
	decrypted := bytes.NewBuffer(nil)

	// Bob decrypts the message.
	pk, _, err := bob.Decrypt(decrypted, received, []PublicKey{bob.PublicKey(), alice.PublicKey()})
	if err != nil {
		panic(err)
	}

	// Bob checks that the sender of the message was indeed Alice.
	if bytes.Equal(pk, alice.PublicKey()) {
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
	publicKeys := []PublicKey{a.PublicKey(), b.PublicKey()}

	eb, err := a.Encrypt(enc, bytes.NewReader(message), publicKeys, 1234)
	if err != nil {
		t.Fatal(err)
	}

	pk, db, err := b.Decrypt(dec, enc, publicKeys)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "public key", pk, a.PublicKey())
	assert.Equal(t, "plaintext", message, dec.Bytes())
	assert.Equal(t, "encrypted bytes", int64(368+1234), eb)
	assert.Equal(t, "decrypted bytes", int64(40), db)
}

func TestPublicKey_MarshalText(t *testing.T) {
	t.Parallel()

	pk := PublicKey("ayellowsubmarineayellowsubmarine")

	text, err := pk.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "marshalled text",
		[]byte("MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSQ"), text)
}

func TestPublicKey_UnmarshalText(t *testing.T) {
	t.Parallel()

	var pk PublicKey

	//goland:noinspection GoNilness
	if err := pk.UnmarshalText([]byte("MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSQ")); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshalled key", PublicKey("ayellowsubmarineayellowsubmarine"), pk)
}

func TestPublicKey_String(t *testing.T) {
	t.Parallel()

	pk := PublicKey("ayellowsubmarineayellowsubmarine")

	assert.Equal(t, "string representation",
		"MF4WK3DMN53XG5LCNVQXE2LOMVQXSZLMNRXXO43VMJWWC4TJNZSQ", pk.String())
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation", sk.PublicKey().String(), sk.String())
}

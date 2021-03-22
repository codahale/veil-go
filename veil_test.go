package veil

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
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
	recipients, err := AddFakes([]*PublicKey{alice.PublicKey(), bob.PublicKey()}, 98)
	if err != nil {
		panic(err)
	}

	// Alice pads the message with random data to disguise its true length.
	padded := Pad(message, 4829)

	// Alice encrypts the message for her, Bob, and the 98 fakes.
	_, err = alice.Encrypt(encrypted, padded, recipients)
	if err != nil {
		panic(err)
	}

	// Alice sends the message to Bob.
	received := bytes.NewReader(encrypted.Bytes())
	decrypted := bytes.NewBuffer(nil)

	// Bob decrypts the message, removing the random padding.
	pk, _, err := bob.Decrypt(Unpad(decrypted), received, []*PublicKey{bob.PublicKey(), alice.PublicKey()})
	if err != nil {
		panic(err)
	}

	// Bob checks that the sender of the message was indeed Alice.
	if alice.PublicKey().Equals(pk) {
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
	publicKeys := []*PublicKey{a.PublicKey(), b.PublicKey()}

	eb, err := a.Encrypt(enc, bytes.NewReader(message), publicKeys)
	if err != nil {
		t.Fatal(err)
	}

	pk, db, err := b.Decrypt(dec, enc, publicKeys)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "public key", pk.q.Bytes(), a.pk.q.Bytes())
	assert.Equal(t, "plaintext", message, dec.Bytes())
	assert.Equal(t, "encrypted bytes", int64(240), eb)
	assert.Equal(t, "decrypted bytes", int64(40), db)
}

func TestPublicKey_Text(t *testing.T) {
	t.Parallel()

	pk := PublicKey{}
	pk2 := PublicKey{}

	// Make a fake, constant public key.
	pk.q.Derive([]byte("ok yeah"))

	// Re-derive the representative.
	pk.rk = pk2rk(&pk.q)

	j, err := json.Marshal(&pk)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "text representation",
		`"3H7PDhB1yaW_eNYMApqRRjWiO2PakBpodGNahRBmoBU"`, string(j))

	if err := json.Unmarshal(j, &pk2); err != nil {
		t.Fatal(err)
	}

	if !pk.q.Equals(&pk2.q) || !bytes.Equal(pk.rk, pk2.rk) {
		t.Error("bad round trip")
	}
}

func TestPublicKey_Binary(t *testing.T) {
	t.Parallel()

	pk := PublicKey{}
	pk2 := PublicKey{}
	buf := bytes.NewBuffer(nil)

	// Make a fake, constant public key.
	pk.q.Derive([]byte("ok yeah"))

	// Re-derive the representative.
	pk.rk = pk2rk(&pk.q)

	e := gob.NewEncoder(buf)
	if err := e.Encode(&pk); err != nil {
		t.Fatal(err)
	}

	d := gob.NewDecoder(buf)
	if err := d.Decode(&pk2); err != nil {
		t.Fatal(err)
	}

	if !pk.q.Equals(&pk2.q) || !bytes.Equal(pk.rk, pk2.rk) {
		t.Error("bad round trip")
	}
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation", sk.PublicKey().String(), sk.String())
}

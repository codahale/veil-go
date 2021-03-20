package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
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
	message := bytes.NewReader([]byte("one two three four I declare a thumb war"))
	encrypted := bytes.NewBuffer(nil)

	// Alice creates a list of recipients -- her and Bob -- but adds 98 fake recipients so Bob won't
	// know the true number of recipients.
	recipients, err := AddFakes(rand.Reader, []*PublicKey{alice.PublicKey(), bob.PublicKey()}, 98)
	if err != nil {
		panic(err)
	}

	// Alice pads the message with random data to disguise its true length.
	padded := Pad(message, rand.Reader, 4829)

	// Alice encrypts the message for her, Bob, and the 98 fakes.
	_, err = alice.Encrypt(encrypted, padded, rand.Reader, recipients)
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

	a, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("one two three four I declare a thumb war")
	enc := bytes.NewBuffer(nil)

	publicKeys := []*PublicKey{a.PublicKey(), b.PublicKey()}

	eb, err := a.Encrypt(enc, bytes.NewReader(message), rand.Reader, publicKeys)
	if err != nil {
		t.Fatal(err)
	}

	enc = bytes.NewBuffer(enc.Bytes())
	dec := bytes.NewBuffer(nil)

	pk, db, err := b.Decrypt(dec, bytes.NewBuffer(enc.Bytes()), publicKeys)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "public key", pk.q.Bytes(), a.pk.q.Bytes())
	assert.Equal(t, "plaintext", message, dec.Bytes())
	assert.Equal(t, "encrypted bytes", 256, eb)
	assert.Equal(t, "decrypted bytes", 40, db)
}

func TestPublicKey_Text(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey(bytes.NewReader(make([]byte, 10*1024)))
	if err != nil {
		t.Fatal(err)
	}

	j, err := json.Marshal(&sk.pk)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "text representation", `"qBtcSssqMHWqbeoOLam8zRVu63OZVDR1l-t79FhVswU"`, string(j))

	var pk2 PublicKey
	if err := json.Unmarshal(j, &pk2); err != nil {
		t.Fatal(err)
	}

	if !sk.pk.q.Equals(&pk2.q) || !bytes.Equal(sk.pk.rk, pk2.rk) {
		t.Error("bad round trip")
	}
}

func TestPublicKey_Binary(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey(bytes.NewReader(make([]byte, 10*1024)))
	if err != nil {
		t.Fatal(err)
	}

	w := bytes.NewBuffer(nil)
	e := gob.NewEncoder(w)

	if err := e.Encode(&sk.pk); err != nil {
		t.Fatal(err)
	}

	var pk2 PublicKey

	r := bytes.NewReader(w.Bytes())
	d := gob.NewDecoder(r)

	if err := d.Decode(&pk2); err != nil {
		t.Fatal(err)
	}

	if !sk.pk.q.Equals(&pk2.q) || !bytes.Equal(sk.pk.rk, pk2.rk) {
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

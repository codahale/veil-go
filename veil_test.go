package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
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

	// Alice encrypts the message for her and Bob.
	_, err = alice.Encrypt(encrypted, message, rand.Reader, []*PublicKey{alice.PublicKey(), bob.PublicKey()})
	if err != nil {
		panic(err)
	}

	// Alice sends the message to Bob.
	received := bytes.NewReader(encrypted.Bytes())
	decrypted := bytes.NewBuffer(nil)

	// Bob decrypts the message and sees that it was encrypted by Alice.
	pk, _, err := bob.Decrypt(decrypted, received, []*PublicKey{bob.PublicKey(), alice.PublicKey()})
	if err != nil {
		panic(err)
	}

	if alice.PublicKey().Equals(pk) {
		fmt.Println("sent by A")
	} else {
		fmt.Println("sent by B")
	}

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

func TestPad(t *testing.T) {
	t.Parallel()

	s := "this is a value"

	padded, err := io.ReadAll(Pad(bytes.NewBufferString(s), rand.Reader, 40))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "padded length", 55, len(padded))

	r := bytes.NewReader(padded)
	if err := Unpad(r); err != nil {
		t.Fatal(err)
	}

	unpadded, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unpadded value", s, string(unpadded))
}

func TestAddFakes(t *testing.T) {
	t.Parallel()

	alice, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bob, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	all, err := AddFakes(rand.Reader, []*PublicKey{alice.PublicKey(), bob.PublicKey()}, 20)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "total count", 22, len(all))

	alices, bobs, others := 0, 0, 0

	for _, pk := range all {
		switch {
		case pk.Equals(alice.PublicKey()):
			alices++
		case pk.Equals(bob.PublicKey()):
			bobs++
		default:
			others++
		}
	}

	assert.Equal(t, "alice count", 1, alices)
	assert.Equal(t, "bob count", 1, bobs)
	assert.Equal(t, "other count", 20, others)
}

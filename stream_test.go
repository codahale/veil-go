package veil

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestAEADStream(t *testing.T) {
	t.Parallel()

	// Set up inputs and outputs.
	src := bytes.NewBufferString("welcome to paradise")
	dst := bytes.NewBuffer(nil)

	// Create an AEAD.
	aead, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		t.Fatal(err)
	}

	// Create an AEAD STREAM.
	stream := &aeadStream{
		aead: aead,
		nonceSequence: nonceSequence{
			nonce: make([]byte, chacha20poly1305.NonceSize),
		},
	}

	// Encrypt the input using a block size of three bytes.
	eb, err := stream.encrypt(dst, src, []byte("ad"), 3)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "encrypted bytes written", 131, eb)

	// Reset the stream and swap inputs and outputs.
	stream.counter = 0
	src = bytes.NewBuffer(dst.Bytes())
	dst = bytes.NewBuffer(nil)

	// Decrypt the output using the same block size.
	db, err := stream.decrypt(dst, src, []byte("ad"), 3)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that the output is the same as the input.
	assert.Equal(t, "encrypted bytes read", 19, db)
	assert.Equal(t, "decrypted message", "welcome to paradise", dst.String())
}

func TestNonceSequence(t *testing.T) {
	t.Parallel()

	ns := nonceSequence{nonce: []byte("abcdefg00000")}

	n1 := ns.next(false)
	assert.Equal(t, "nonce sequence",
		[]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x00, 0x00, 0x00, 0x01, 0x00}, n1)

	n2 := ns.next(false)
	assert.Equal(t, "nonce sequence",
		[]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x00, 0x00, 0x00, 0x02, 0x00}, n2)

	n3 := ns.next(true)
	assert.Equal(t, "nonce sequence",
		[]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x00, 0x00, 0x00, 0x03, 0x01}, n3)
}

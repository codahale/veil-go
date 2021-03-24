package veil

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestAEADStream(t *testing.T) {
	t.Parallel()

	// Constants.
	key := []byte("this is ok")
	ad := make([]byte, 19)

	// Set up inputs and outputs.
	src := bytes.NewBufferString("welcome to paradise")
	dst := bytes.NewBuffer(nil)

	// Create an AEAD writer.
	w := newAEADWriter(dst, key, ad, 9)

	// Encrypt the input.
	pn, err := io.Copy(w, src)
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to flush everything.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Check to see that we wrote the expected number of bytes.
	assert.Equal(t, "plaintext bytes written", int64(19), pn)

	// Swap inputs and outputs.
	src = dst
	dst = bytes.NewBuffer(nil)

	// Create a reader.
	r := newAEADReader(src, key, ad, 9)

	// Decrypt the input.
	cn, err := io.Copy(dst, r)
	if err != nil {
		t.Fatal(err)
	}

	// Check to see that we read the expected number of bytes.
	assert.Equal(t, "ciphertext bytes written", int64(19), cn)

	// Check to see that we decrypted the original message.
	assert.Equal(t, "plaintext", "welcome to paradise", dst.String())
}

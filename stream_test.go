package veil

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestAEADStream(t *testing.T) {
	t.Parallel()

	// Constants.
	key := make([]byte, chacha20poly1305.KeySize)
	nonce := make([]byte, chacha20poly1305.NonceSize)

	// Set up inputs and outputs.
	src := bytes.NewBufferString("welcome to paradise")
	dst := bytes.NewBuffer(nil)

	// Create an AEAD writer.
	w, err := newAEADWriter(dst, key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt the input.
	eb, err := io.Copy(w, src)
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to flush everything.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Check to see that we wrote the expected number of bytes.
	assert.Equal(t, "encrypted bytes written", int64(19), eb)

	// Swap inputs and outputs.
	src = bytes.NewBuffer(dst.Bytes())
	dst = bytes.NewBuffer(nil)

	// Create an AEAD reader.
	r, err := newAEADReader(src, key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt the output.
	db, err := io.Copy(dst, r)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that the output is the same as the input.
	assert.Equal(t, "encrypted bytes read", int64(19), db)
	assert.Equal(t, "decrypted message", "welcome to paradise", dst.String())
}

func TestAEADStream_Invalid(t *testing.T) {
	t.Parallel()

	// Constants.
	key := make([]byte, chacha20poly1305.KeySize)
	nonce := make([]byte, chacha20poly1305.NonceSize)

	// Set up inputs and outputs.
	src := bytes.NewBufferString("welcome to paradise")
	dst := bytes.NewBuffer(nil)

	// Create an AEAD writer.
	w, err := newAEADWriter(dst, key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt the input.
	eb, err := io.Copy(w, src)
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to flush everything.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Check to see that we wrote the expected number of bytes.
	assert.Equal(t, "encrypted bytes written", int64(19), eb)

	// Corrupt the ciphertext.
	_, _ = dst.WriteString("bogus")

	// Swap inputs and outputs.
	src = bytes.NewBuffer(dst.Bytes())
	dst = bytes.NewBuffer(nil)

	// Create an AEAD reader.
	r, err := newAEADReader(src, key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt the output.
	if _, err = io.Copy(dst, r); err == nil {
		t.Fatal("should not have decrypted successfully")
	}
}

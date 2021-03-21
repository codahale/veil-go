package veil

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestAEADStream(t *testing.T) {
	t.Parallel()

	// Set up inputs and outputs.
	src := bufio.NewReader(bytes.NewBufferString("welcome to paradise"))
	dst := bytes.NewBuffer(nil)

	// Create an AEAD STREAM.
	stream := newAEADStream(make([]byte, chacha20poly1305.KeySize))

	// Encrypt the input using a block size of three bytes.
	eb, err := stream.encrypt(dst, src, []byte("ad"), 3)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "encrypted bytes written", 131, eb)

	// Reset the stream and swap inputs and outputs.
	stream = newAEADStream(make([]byte, chacha20poly1305.KeySize))
	src = bufio.NewReader(bytes.NewBuffer(dst.Bytes()))
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

func TestAEADStream_Invalid(t *testing.T) {
	t.Parallel()

	// Set up inputs and outputs.
	src := bufio.NewReader(bytes.NewBufferString("welcome to paradise"))
	dst := bytes.NewBuffer(nil)

	// Create an AEAD STREAM.
	stream := newAEADStream(make([]byte, chacha20poly1305.KeySize))

	// Encrypt the input using a block size of three bytes.
	if _, err := stream.encrypt(dst, src, []byte("ad"), 3); err != nil {
		t.Fatal(err)
	}

	// Corrupt the ciphertext.
	_, _ = dst.WriteString("bogus")

	// Reset the stream and swap inputs and outputs.
	stream = newAEADStream(make([]byte, chacha20poly1305.KeySize))
	src = bufio.NewReader(bytes.NewBuffer(dst.Bytes()))
	dst = bytes.NewBuffer(nil)

	// Decrypt the output using the same block size.
	_, err := stream.decrypt(dst, src, []byte("ad"), 3)
	if err == nil {
		t.Error("should have returned an error but didn't")
	}

	// Ensure that the output is spoiled.
	assert.Equal(t, "decrypted message",
		"welcome to paradis\nINVALID CIPHERTEXT\nDO NOT TRUST", dst.String())
}

func TestNonceSequence(t *testing.T) {
	t.Parallel()

	var ns nonceSequence

	n1 := ns.next(false)
	assert.Equal(t, "nonce sequence",
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}, n1)

	n2 := ns.next(false)
	assert.Equal(t, "nonce sequence",
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00}, n2)

	n3 := ns.next(true)
	assert.Equal(t, "nonce sequence",
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01}, n3)
}

func TestBlockReader_Exact(t *testing.T) {
	t.Parallel()

	r := bufio.NewReader(io.LimitReader(rand.Reader, blockSize*6))
	br := newBlockReader(r, blockSize)

	var counts []int

	for {
		block, final, err := br.read()
		if err != nil {
			t.Fatal(err)
		}

		counts = append(counts, len(block))

		if final {
			break
		}
	}

	assert.Equal(t, "block sizes",
		[]int{1048576, 1048576, 1048576, 1048576, 1048576, 1048576}, counts)
}

func TestBlockReader_Odd(t *testing.T) {
	t.Parallel()

	r := bufio.NewReader(io.LimitReader(rand.Reader, (blockSize*6)+100))
	br := newBlockReader(r, blockSize)

	var counts []int

	for {
		block, final, err := br.read()
		if err != nil {
			t.Fatal(err)
		}

		counts = append(counts, len(block))

		if final {
			break
		}
	}

	assert.Equal(t, "block sizes",
		[]int{1048576, 1048576, 1048576, 1048576, 1048576, 1048576, 100}, counts)
}

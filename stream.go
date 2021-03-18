package veil

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// aeadStream encrypts and decrypts streams of data using Rogaway's AEAD STREAM construction.
// See https://eprint.iacr.org/2015/189.pdf.
type aeadStream struct {
	aead cipher.AEAD
	nonceSequence
}

func (as *aeadStream) encrypt(dst io.Writer, src io.Reader, ad []byte, blockSize int) (int, error) {
	// Allocate a buffer big enough for a block of ciphertext.
	buf := make([]byte, blockSize+as.aead.Overhead())
	wn := 0
	final := false

	for {
		// Read a block of plaintext.
		rn, err := io.ReadFull(src, buf[:blockSize])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			final = true
		} else if err != nil {
			return wn, err
		}

		// Encrypt the block.
		buf = as.aead.Seal(buf[:0], as.next(final), buf[:rn], ad)

		// Write the encrypted block.
		n, err := dst.Write(buf)
		wn += n

		if err != nil {
			// If there was an error writing, return the number of bytes written and the error.
			return wn, err
		} else if final {
			// If this was the last block, return the number of bytes written.
			return wn, nil
		}
	}
}

func (as *aeadStream) decrypt(dst io.Writer, src io.Reader, ad []byte, blockSize int) (int, error) {
	blockSize += as.aead.Overhead()
	buf := make([]byte, blockSize)
	wn := 0
	final := false

	for {
		// Read a block of ciphertext, plus AEAD tag.
		rn, err := io.ReadFull(src, buf[:blockSize])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			final = true
		} else if err != nil {
			return wn, err
		}

		// Decrypt the block.
		buf, err = as.aead.Open(buf[:0], as.next(final), buf[:rn], ad)
		if err != nil {
			return wn, err
		}

		// Write the decrypted block.
		n, err := dst.Write(buf)
		wn += n

		if err != nil {
			// If there was an error writing, return the number of bytes written and the error.
			return wn, err
		} else if final {
			// If this was the last block, return the number of bytes written.
			return wn, nil
		}
	}
}

type nonceSequence struct {
	nonce   []byte
	counter uint32
}

func (ns *nonceSequence) next(final bool) []byte {
	// Increment the counter, checking for overflows.
	ns.counter++
	if ns.counter == 0 {
		panic("stream counter overflow")
	}

	// Append the counter value to the nonce prefix.
	binary.BigEndian.PutUint32(ns.nonce[len(ns.nonce)-5:], ns.counter)

	// Determine the continuation byte.
	var continuation byte
	if final {
		continuation = 1
	}

	// Set the continuation byte.
	ns.nonce[len(ns.nonce)-1] = continuation

	// Return the new nonce.
	return ns.nonce
}

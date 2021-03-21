package veil

import (
	"bufio"
	"crypto/cipher"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// aeadStream encrypts and decrypts streams of data using Rogaway's AEAD STREAM construction.
// See https://eprint.iacr.org/2015/189.pdf.
type aeadStream struct {
	aead cipher.AEAD
	nonceSequence
}

func newAEADStream(key []byte) *aeadStream {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	return &aeadStream{
		aead: aead,
	}
}

func (as *aeadStream) encrypt(dst io.Writer, src *bufio.Reader, ad []byte, blockSize int) (int, error) {
	br := newBlockReader(src, blockSize)
	wn := 0

	for {
		// Read a block of plaintext.
		block, final, err := br.read()
		if err != nil {
			return wn, err
		}

		// Encrypt the block using the next nonce in the sequence.
		block = as.aead.Seal(block[:0], as.next(final), block, ad)

		// Write the encrypted block.
		n, err := dst.Write(block)
		wn += n

		if err != nil {
			// If there was an error writing, return the number of bytes written and the error.
			return wn, err
		}

		if final {
			// If this was the last block, return the number of bytes written.
			return wn, nil
		}
	}
}

func (as *aeadStream) decrypt(dst io.Writer, src *bufio.Reader, ad []byte, blockSize int) (int, error) {
	br := newBlockReader(src, blockSize+as.aead.Overhead())
	wn := 0

	for {
		// Read a block of ciphertext, plus AEAD tag.
		block, final, err := br.read()
		if err != nil {
			return wn, err
		}

		// Decrypt the block using the next nonce in the sequence.
		block, err = as.aead.Open(block[:0], as.next(final), block, ad)
		if err != nil {
			// If the block is invalid, spoil the output to ensure it's not trusted, even if it's
			// not discarded.
			n, _ := io.WriteString(dst, "\nINVALID CIPHERTEXT\nDO NOT TRUST")

			return wn + n, ErrInvalidCiphertext
		}

		// Write the decrypted block.
		n, err := dst.Write(block)
		wn += n

		if err != nil {
			// If there was an error writing, return the number of bytes written and the error.
			return wn, err
		}

		if final {
			// If this was the last block, return the number of bytes written.
			return wn, nil
		}
	}
}

type nonceSequence struct {
	ctr [chacha20poly1305.NonceSize]byte
}

func (ns *nonceSequence) next(final bool) []byte {
	for i := len(ns.ctr) - 2; i >= 0; i-- {
		ns.ctr[i]++

		if i == 0 && ns.ctr[i] == 0 {
			panic("counter overflow")
		} else if ns.ctr[i] != 0 {
			break
		}
	}

	// Set the continuation byte, if needed.
	if final {
		ns.ctr[chacha20poly1305.NonceSize-1] = 1
	}

	// Return the new nonce.
	return ns.ctr[:]
}

type blockReader struct {
	r         *bufio.Reader
	blockSize int
	in        []byte
}

func newBlockReader(src *bufio.Reader, blockSize int) *blockReader {
	return &blockReader{
		r:         src,
		blockSize: blockSize,
		in:        make([]byte, blockSize+1),
	}
}

func (br *blockReader) read() ([]byte, bool, error) {
	final := false

	// Read a block of data plus an extra byte. If this is the very last block of an
	// evenly-divisible input, we'll get a full block and an EOF.
	n, err := io.ReadFull(br.r, br.in[:br.blockSize+1])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// If we hit an EOF, expected and/or otherwise, this is the final block. If we didn't
			// hit an EOF, there's at least one more byte to be read.
			final = true
		} else {
			return nil, false, err
		}
	}

	// If we read a full block, ignore the last byte.
	if n > br.blockSize {
		// Pretend we didn't see it.
		n--

		// And back up the input by one byte.
		if err := br.r.UnreadByte(); err != nil {
			return nil, false, err
		}
	}

	return br.in[:n], final, nil
}

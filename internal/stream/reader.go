package stream

import (
	"errors"
	"io"

	"github.com/codahale/veil/internal/ratchet"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// reader reads blocks of AEAD-encrypted data and decrypts them using a ratcheting key.
type reader struct {
	r             io.Reader
	keys          *ratchet.Sequence
	ad            []byte
	plaintext     []byte
	plaintextPos  int
	ciphertext    []byte
	ciphertextPos int
}

func NewReader(src io.Reader, key, additionalData []byte, blockSize int) io.Reader {
	return &reader{
		keys:       ratchet.New(key, chacha20.KeySize+chacha20.NonceSize),
		r:          src,
		ad:         additionalData,
		ciphertext: make([]byte, blockSize+poly1305.TagSize+1), // extra byte for determining last block
	}
}

func (r *reader) Read(p []byte) (n int, err error) {
	// If we have buffered plaintext sufficient for this read, return it.
	if r.plaintextPos < len(r.plaintext) {
		n := copy(p, r.plaintext[r.plaintextPos:])
		r.plaintextPos += n

		return n, nil
	}

	// Otherwise, read more ciphertext.
	r.plaintextPos = 0
	ctLim := len(r.ciphertext)

	n, err = io.ReadFull(r.r, r.ciphertext[r.ciphertextPos:ctLim])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, err
	}

	// Assume we read a full buffer; pretend we didn't read the last byte.
	lastSegment := false
	segment := r.ciphertextPos + n - 1

	// If we got an "unexpected EOF", it's because we read the final block, so don't pretend we
	// didn't read the last byte.
	if err != nil {
		lastSegment = true
		segment = r.ciphertextPos + n
	}

	if segment < 0 {
		return 0, io.ErrUnexpectedEOF
	}

	// Decrypt the block we just read.
	r.plaintext, err = r.decrypt(r.ciphertext[:segment], lastSegment)
	if err != nil {
		return 0, err
	}

	// If that wasn't the last block, make the last byte visible again so it can be the first byte
	// of the next block.
	if !lastSegment {
		remainderOffset := segment
		r.ciphertext[0] = r.ciphertext[remainderOffset]
		r.ciphertextPos = 1
	}

	// Satisfy the read with the plaintext buffer.
	n = copy(p, r.plaintext)
	r.plaintextPos = n

	return n, nil
}

func (r *reader) decrypt(ciphertext []byte, final bool) ([]byte, error) {
	key := r.keys.Next(final)

	aead, err := chacha20poly1305.New(key[:chacha20.KeySize])
	if err != nil {
		panic(err)
	}

	return aead.Open(nil, key[chacha20.KeySize:], ciphertext, r.ad)
}

var _ io.Reader = &reader{}

package streamio

import (
	"errors"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/authenc"
)

// NewReader returns an io.Reader which reads encrypted blocks from src and decrypts them using the
// veil.authenc.stream STROBE protocol.
func NewReader(src io.Reader, key, encryptedHeaders []byte, blockSize int) io.Reader {
	return &reader{
		stream:     authenc.NewStreamOpener(key, encryptedHeaders, blockSize, authenc.TagSize),
		r:          src,
		ciphertext: make([]byte, blockSize+authenc.TagSize+1), // extra byte for determining last block
	}
}

type reader struct {
	r             io.Reader
	stream        *authenc.StreamOpener
	plaintext     []byte
	plaintextPos  int
	ciphertext    []byte
	ciphertextPos int
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
	r.plaintext, err = r.stream.Open(r.ciphertext[:segment], lastSegment)
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

var _ io.Reader = &reader{}

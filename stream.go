package veil

import (
	"errors"
	"io"

	"github.com/codahale/veil/internal/ratchet"
)

// aeadReader reads blocks of AEAD-encrypted data and decrypts them using a ratcheting key.
type aeadReader struct {
	r             io.Reader
	keys          *ratchet.Sequence
	ad            []byte
	plaintext     []byte
	plaintextPos  int
	ciphertext    []byte
	ciphertextPos int
}

func newAEADReader(src io.Reader, key, additionalData []byte, blockSize int) io.Reader {
	return &aeadReader{
		keys:       ratchet.New(key, aeadKeySize+aeadIVSize),
		r:          src,
		ad:         additionalData,
		ciphertext: make([]byte, blockSize+aeadOverhead+1), // extra byte for determining last block
	}
}

func (r *aeadReader) Read(p []byte) (n int, err error) {
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

func (r *aeadReader) decrypt(ciphertext []byte, final bool) ([]byte, error) {
	key := r.keys.Next(final)
	aead := newHMACAEAD(key[:aeadKeySize])

	return aead.Open(nil, key[aeadKeySize:], ciphertext, r.ad)
}

var _ io.Reader = &aeadReader{}

// aeadWriter writes blocks of AEAD-encrypted data using a ratcheting key.
type aeadWriter struct {
	keys         *ratchet.Sequence
	w            io.Writer
	ad           []byte
	plaintext    []byte
	plaintextPos int
	ciphertext   []byte
	closed       bool
}

func newAEADWriter(dst io.Writer, key, additionalData []byte, blockSize int) io.WriteCloser {
	return &aeadWriter{
		keys:      ratchet.New(key, aeadKeySize+aeadIVSize),
		w:         dst,
		ad:        additionalData,
		plaintext: make([]byte, blockSize),
	}
}

func (w *aeadWriter) Write(p []byte) (n int, err error) {
	// Early exit if we're closed.
	if w.closed {
		return 0, io.ErrClosedPipe
	}

	pos := 0

	for {
		// Copy from the written slice to our plaintext buffer.
		ptLim := len(w.plaintext)
		n := copy(w.plaintext[w.plaintextPos:ptLim], p[pos:])
		w.plaintextPos += n
		pos += n

		// If we don't have a full buffer, early exit.
		if pos == len(p) {
			break
		}

		// Otherwise, encrypt the plaintext buffer.
		w.ciphertext = w.encrypt(w.plaintext[:ptLim], false)

		// And write the ciphertext to the underlying writer.
		if _, err := w.w.Write(w.ciphertext); err != nil {
			return pos, err
		}

		w.plaintextPos = 0
	}

	return pos, nil
}

func (w *aeadWriter) Close() error {
	if w.closed {
		return nil
	}

	w.ciphertext = w.encrypt(w.plaintext[:w.plaintextPos], true)

	if _, err := w.w.Write(w.ciphertext); err != nil {
		return err
	}

	w.plaintextPos = 0
	w.closed = true

	return nil
}

func (w *aeadWriter) encrypt(plaintext []byte, final bool) []byte {
	key := w.keys.Next(final)
	aead := newHMACAEAD(key[:aeadKeySize])

	return aead.Seal(nil, key[aeadKeySize:], plaintext, w.ad)
}

var _ io.WriteCloser = &aeadWriter{}

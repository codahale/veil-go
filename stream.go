package veil

import (
	"errors"
	"io"
)

// aeadReader reads blocks of AEAD-encrypted data and decrypts them using a ratcheting key.
type aeadReader struct {
	r             io.Reader
	keys          *keyRatchet
	ad            []byte
	plaintext     []byte
	plaintextPos  int
	ciphertext    []byte
	ciphertextPos int
}

func newAEADReader(src io.Reader, key, additionalData []byte, blockSize int) io.Reader {
	return &aeadReader{
		keys:       newKeyRatchet(key),
		r:          src,
		ad:         additionalData,
		ciphertext: make([]byte, blockSize+aeadOverhead+1),
	}
}

func (r *aeadReader) Read(p []byte) (n int, err error) {
	if r.plaintextPos < len(r.plaintext) {
		n := copy(p, r.plaintext[r.plaintextPos:])
		r.plaintextPos += n

		return n, nil
	}

	r.plaintextPos = 0
	ctLim := len(r.ciphertext)

	n, err = io.ReadFull(r.r, r.ciphertext[r.ciphertextPos:ctLim])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, err
	}

	var (
		lastSegment bool
		segment     int
	)

	if err != nil {
		lastSegment = true
		segment = r.ciphertextPos + n
	} else {
		segment = r.ciphertextPos + n - 1
	}

	if segment < 0 {
		return 0, io.ErrUnexpectedEOF
	}

	r.plaintext, err = r.decrypt(r.ciphertext[:segment], lastSegment)
	if err != nil {
		return 0, err
	}

	if !lastSegment {
		remainderOffset := segment
		r.ciphertext[0] = r.ciphertext[remainderOffset]
		r.ciphertextPos = 1
	}

	n = copy(p, r.plaintext)
	r.plaintextPos = n

	return n, nil
}

func (r *aeadReader) decrypt(ciphertext []byte, final bool) ([]byte, error) {
	key, iv := r.keys.ratchet(final)
	aead := newHMACAEAD(key)

	return aead.Open(nil, iv, ciphertext, r.ad)
}

var _ io.Reader = &aeadReader{}

// aeadWriter writes blocks of AEAD-encrypted data using a ratcheting key.
type aeadWriter struct {
	keys         *keyRatchet
	w            io.Writer
	ad           []byte
	plaintext    []byte
	plaintextPos int
	ciphertext   []byte
	closed       bool
}

func newAEADWriter(dst io.Writer, key, additionalData []byte, blockSize int) io.WriteCloser {
	return &aeadWriter{
		keys:      newKeyRatchet(key),
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
		ptLim := len(w.plaintext)
		n := copy(w.plaintext[w.plaintextPos:ptLim], p[pos:])
		w.plaintextPos += n
		pos += n

		if pos == len(p) {
			break
		}

		w.ciphertext = w.encrypt(w.plaintext[:ptLim], false)

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
	key, iv := w.keys.ratchet(final)
	aead := newHMACAEAD(key)

	return aead.Seal(nil, iv, plaintext, w.ad)
}

var _ io.WriteCloser = &aeadWriter{}

package stream

import (
	"io"

	"github.com/codahale/veil/internal/ratchet"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// writer writes blocks of AEAD-encrypted data using a ratcheting key.
type writer struct {
	keys         *ratchet.Sequence
	w            io.Writer
	ad           []byte
	plaintext    []byte
	plaintextPos int
	ciphertext   []byte
	closed       bool
}

func NewWriter(dst io.Writer, key, additionalData []byte, blockSize int) io.WriteCloser {
	return &writer{
		keys:      ratchet.New(key, chacha20.KeySize+chacha20.NonceSize),
		w:         dst,
		ad:        additionalData,
		plaintext: make([]byte, blockSize),
	}
}

func (w *writer) Write(p []byte) (n int, err error) {
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

func (w *writer) Close() error {
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

func (w *writer) encrypt(plaintext []byte, final bool) []byte {
	key := w.keys.Next(final)

	aead, err := chacha20poly1305.New(key[:chacha20.KeySize])
	if err != nil {
		panic(err)
	}

	return aead.Seal(nil, key[chacha20.KeySize:], plaintext, w.ad)
}

var _ io.WriteCloser = &writer{}

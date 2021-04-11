package streamio

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/stream"
)

// NewWriter returns an io.Writer which groups writes into blocks, encrypts them with the
// veil.stream STROBE protocol, and writes them to dst.
func NewWriter(dst io.Writer, key, associatedData []byte) io.WriteCloser {
	return &writer{
		w:         dst,
		stream:    stream.NewSealer(key, associatedData),
		plaintext: make([]byte, stream.BlockSize),
	}
}

type writer struct {
	w            io.Writer
	stream       *stream.Sealer
	plaintext    []byte
	plaintextPos int
	ciphertext   []byte
	closed       bool
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
		w.ciphertext = w.stream.Seal(w.ciphertext[:0], w.plaintext[:ptLim], false)

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

	w.ciphertext = w.stream.Seal(w.ciphertext[:0], w.plaintext[:w.plaintextPos], true)

	if _, err := w.w.Write(w.ciphertext); err != nil {
		return err
	}

	w.plaintextPos = 0
	w.closed = true

	return nil
}

var _ io.WriteCloser = &writer{}

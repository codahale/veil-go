package streamio

import (
	"errors"
	"io"
)

type SignatureReader struct {
	Signature []byte

	in          io.Reader
	scratch     []byte
	trailerUsed int
	error       bool
	eof         bool
}

func NewSignatureReader(src io.Reader, sigSize int) *SignatureReader {
	return &SignatureReader{
		Signature: make([]byte, sigSize),
		in:        src,
		scratch:   make([]byte, sigSize),
	}
}

//nolint:gocognit,nakedret // This is just complicated.
func (tr *SignatureReader) Read(buf []byte) (n int, err error) {
	if tr.error {
		err = io.ErrUnexpectedEOF
		return
	}

	if tr.eof {
		err = io.EOF
		return
	}

	// If we haven't yet filled the trailer buffer then we must do that
	// first.
	for tr.trailerUsed < len(tr.Signature) {
		n, err = tr.in.Read(tr.Signature[tr.trailerUsed:])
		tr.trailerUsed += n

		if errors.Is(err, io.EOF) {
			if tr.trailerUsed != len(tr.Signature) {
				n = 0
				err = io.ErrUnexpectedEOF
				tr.error = true

				return
			}

			tr.eof = true
			n = 0

			return
		}

		if err != nil {
			n = 0

			return
		}
	}

	// If it's a short read then we read into a temporary buffer and shift
	// the data into the caller's buffer.
	if len(buf) <= len(tr.Signature) {
		n, err = readFull(tr.in, tr.scratch[:len(buf)])
		copy(buf, tr.Signature[:n])
		copy(tr.Signature, tr.Signature[n:])
		copy(tr.Signature[len(tr.Signature)-n:], tr.scratch)

		if n < len(buf) {
			tr.eof = true
			err = io.EOF
		}

		return
	}

	n, err = tr.in.Read(buf[len(tr.Signature):])
	copy(buf, tr.Signature)
	copy(tr.Signature, buf[n:])

	if errors.Is(err, io.EOF) {
		tr.eof = true
	}

	return
}

func readFull(r io.Reader, buf []byte) (n int, err error) {
	n, err = io.ReadFull(r, buf)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}

	return
}

// Package kemkdf provides the underlying STROBE protocol for Veil's message hashing.
//
// Message hashing is as follows, given the size of the resulting digest N and a series of message
// chunks M0, M1, and M2:
//
//     INIT('veil.msghash',        level=256)
//     AD(BIG_ENDIAN_U32(N),       meta=true)
//     SEND_CLR('',                streaming=false)
//     SEND_CLR(M0,                streaming=true)
//     SEND_CLR(M1,                streaming=true)
//     SEND_CLR(M2,                streaming=true)
//     SEND_MAC(N)
//
// The resulting N-byte MAC is used as the digest.
package msghash

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

type Writer struct {
	s          *strobe.Strobe
	digestSize int
}

func NewWriter(digestSize int) *Writer {
	s, err := strobe.New("veil.msghash", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	if err := s.AD(protocols.BigEndianU32(digestSize), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	if err := s.SendCLR(nil, &strobe.Options{Streaming: false}); err != nil {
		panic(err)
	}

	return &Writer{s: s, digestSize: digestSize}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	if err := w.s.SendCLR(p, &strobe.Options{Streaming: true}); err != nil {
		panic(err)
	}

	return len(p), nil
}

func (w *Writer) Digest() []byte {
	digest := make([]byte, w.digestSize)
	if err := w.s.SendMAC(digest, &strobe.Options{}); err != nil {
		panic(err)
	}

	return digest
}

var _ io.Writer = &Writer{}

// Package kemkdf provides the underlying STROBE protocol for Veil's message hashing.
//
// Message hashing is as follows, given the size of the resulting digest N and a series of message
// chunks M0, M1, and M2:
//
//     INIT('veil.msghash', level=256)
//     AD(LE_U32(N),        meta=true)
//     SEND_CLR('',         streaming=false)
//     SEND_CLR(M0,         streaming=true)
//     SEND_CLR(M1,         streaming=true)
//     SEND_CLR(M2,         streaming=true)
//     SEND_MAC(N)
//
// The resulting N-byte MAC is used as the digest.
package msghash

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

const (
	// DigestSize is the recommended size of msghash digests in bytes.
	DigestSize = 64
)

type Writer struct {
	msghash    *strobe.Strobe
	digestSize int
}

func NewWriter(digestSize int) *Writer {
	msghash := protocols.New("veil.msghash")

	// Include the digest size as associated data.
	protocols.Must(msghash.AD(protocols.LittleEndianU32(digestSize), &strobe.Options{Meta: true}))

	// Send a 0-byte block of clear text to enable future streaming clear text.
	protocols.Must(msghash.SendCLR(nil, &strobe.Options{Streaming: false}))

	return &Writer{msghash: msghash, digestSize: digestSize}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	// Send the block as streaming clear text.
	protocols.Must(w.msghash.SendCLR(p, &strobe.Options{Streaming: true}))

	return len(p), nil
}

func (w *Writer) Digest() []byte {
	// Calculate and send a MAC of the previously sent clear text.
	digest := make([]byte, w.digestSize)
	protocols.Must(w.msghash.SendMAC(digest, &strobe.Options{}))

	return digest
}

var _ io.Writer = &Writer{}

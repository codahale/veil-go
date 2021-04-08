// Package armor provides a simple way to encode Veil encrypted and signed messages as ASCII.
//
// An armored message is encoded with URL-safe base64 and wrapped at 76 characters. While not
// particularly efficient, this provides maximal compatibility with text-based systems.
package armor

import (
	"encoding/base64"
	"io"

	"github.com/emersion/go-textwrapper"
)

// NewEncoder returns an io.WriteCloser which will armor data before writing it to dst.
func NewEncoder(dst io.Writer) io.WriteCloser {
	return base64.NewEncoder(base64.URLEncoding, textwrapper.New(dst, "\n", 76))
}

// NewDecoder returns an io.ReadCloser which will de-armor data after reading it from src.
func NewDecoder(src io.Reader) io.ReadCloser {
	return io.NopCloser(base64.NewDecoder(base64.URLEncoding, src))
}

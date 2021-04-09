// Package armor provides a simple way to encode Veil encrypted and signed messages as ASCII.
package armor

import (
	"io"

	"golang.org/x/crypto/openpgp/armor"
)

// NewEncoder returns an io.WriteCloser which will armor data before writing it to dst.
func NewEncoder(dst io.Writer) (io.WriteCloser, error) {
	return armor.Encode(dst, "VEIL", nil)
}

// NewDecoder returns an io.ReadCloser which will de-armor data after reading it from src.
func NewDecoder(src io.Reader) (io.ReadCloser, error) {
	dec, err := armor.Decode(src)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(dec.Body), nil
}

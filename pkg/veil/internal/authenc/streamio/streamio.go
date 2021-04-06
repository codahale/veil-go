// Package streamio provides io.Reader and io.Writer implementations for the veil.authenc.stream
// STROBE protocol.
package streamio

const (
	// BlockSize is the recommend block size for AEAD streams, as selected by it looking pretty.
	BlockSize = 64 * 1024 // 64KiB
)

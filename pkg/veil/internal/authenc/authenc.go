// Package authenc provides the underlying STROBE protocols for Veil's authenticated encryption.
package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/sammyne/strobe"
)

//nolint:gosec // these are not secrets, dummy
const (
	KeySize = 32 // KeySize is the symmetric key size in bytes.
	TagSize = 16 // TagSize is the authentication tag size in bytes.

	headerProto    = "veil.authenc.header"
	secretKeyProto = "veil.authenc.secret-key"
)

func newAE(protocol string, key []byte, tagSize int) *strobe.Strobe {
	// Create a new protocol.
	ae := internal.Strobe(protocol)

	// Add the tag size to the protocol.
	internal.Must(ae.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Initialize the protocol with the key.
	internal.Must(ae.KEY(internal.Copy(key), false))

	return ae
}

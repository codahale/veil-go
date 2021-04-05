// Package authenc provides the underlying STROBE protocols for Veil's authenticated encryption.
package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
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
	ae := protocols.New(protocol)

	// Add the tag size to the protocol.
	protocols.Must(ae.AD(protocols.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Copy the key.
	k := make([]byte, len(key))
	copy(k, key)

	// Initialize the protocol with the key.
	protocols.Must(ae.KEY(k, false))

	return ae
}

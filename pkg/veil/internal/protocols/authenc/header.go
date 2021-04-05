package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// EncryptHeader encrypts the header with the key, appending a tag of the given size for
// authentication.
func EncryptHeader(key []byte, pubEH *ristretto255.Element, header []byte, tagSize int) []byte {
	// Initialize a new protocol.
	authenc := newProtocol(headerProto, key, tagSize)

	// Witness the ephemeral public key.
	protocols.Must(authenc.SendCLR(pubEH.Encode(nil), &strobe.Options{}))

	// Copy the plaintext to a buffer.
	ciphertext := make([]byte, len(header), len(header)+tagSize)
	copy(ciphertext, header)

	// Encrypt it in place.
	protocols.MustENC(authenc.SendENC(ciphertext, &strobe.Options{}))

	// Create a MAC.
	tag := make([]byte, tagSize)
	protocols.Must(authenc.SendMAC(tag, &strobe.Options{}))

	// Return the ciphertext and tag.
	return append(ciphertext, tag...)
}

// DecryptHeader decrypts the encrypted header using the key, detaching and verifying the
// authentication tag of the given size.
func DecryptHeader(key []byte, pubEH *ristretto255.Element, encHeader []byte, tagSize int) ([]byte, error) {
	authenc := newProtocol(headerProto, key, tagSize)

	// Witness the ephemeral public key.
	protocols.Must(authenc.RecvCLR(pubEH.Encode(nil), &strobe.Options{}))

	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(encHeader)-tagSize)
	copy(plaintext, encHeader[:len(encHeader)-tagSize])

	// Copy the tag.
	tag := make([]byte, tagSize)
	copy(tag, encHeader[len(encHeader)-tagSize:])

	// Decrypt it in place.
	protocols.MustENC(authenc.RecvENC(plaintext, &strobe.Options{}))

	// Verify the MAC.
	if err := authenc.RecvMAC(tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the plaintext.
	return plaintext, nil
}

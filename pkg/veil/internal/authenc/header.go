package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// EncryptHeader encrypts the header with the key, appending a tag of the given size for
// authentication.
//
// Encryption of a message header is performed as follows, given a key K, an ephemeral public key Q,
// a plaintext header H, and a tag size N:
//
//     INIT('veil.authenc.header', level=256)
//     AD(LE_U32(N)),              meta=true)
//     KEY(K)
//     SEND_CLR(Q)
//     SEND_ENC(H)
//     SEND_MAC(N)
//
// The ciphertext and T-byte tag are then returned.
func EncryptHeader(key []byte, pubEH *ristretto255.Element, header []byte, tagSize int) []byte {
	// Initialize a new protocol.
	ae := newAE(headerProto, key, tagSize)

	// Send the ephemeral public key.
	internal.Must(ae.SendCLR(pubEH.Encode(nil), &strobe.Options{}))

	// Copy the plaintext to a buffer.
	ciphertext := make([]byte, len(header), len(header)+tagSize)
	copy(ciphertext, header)

	// Encrypt it in place.
	internal.MustENC(ae.SendENC(ciphertext, &strobe.Options{}))

	// Create a MAC.
	tag := make([]byte, tagSize)
	internal.Must(ae.SendMAC(tag, &strobe.Options{}))

	// Return the ciphertext and tag.
	return append(ciphertext, tag...)
}

// DecryptHeader decrypts the encrypted header using the key, detaching and verifying the
// authentication tag of the given size.
//
// Decryption of a message header is performed as follows, given a key K, an ephemeral public key Q,
// a ciphertext C, an authentication tag T, and a tag size N:
//
//     INIT('veil.authenc.header', level=256)
//     AD(LE_U32(N)),              meta=true)
//     KEY(K)
//     RECV_CLR(Q)
//     RECV_ENC(C)
//     RECV_MAC(T)
//
// If the RECV_MAC operation is successful, the plaintext header is returned.
func DecryptHeader(key []byte, pubEH *ristretto255.Element, encHeader []byte, tagSize int) ([]byte, error) {
	ae := newAE(headerProto, key, tagSize)

	// Receive the ephemeral public key.
	internal.Must(ae.RecvCLR(pubEH.Encode(nil), &strobe.Options{}))

	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(encHeader)-tagSize)
	copy(plaintext, encHeader[:len(encHeader)-tagSize])

	// Copy the tag.
	tag := make([]byte, tagSize)
	copy(tag, encHeader[len(encHeader)-tagSize:])

	// Decrypt it in place.
	internal.MustENC(ae.RecvENC(plaintext, &strobe.Options{}))

	// Verify the MAC.
	if err := ae.RecvMAC(tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the plaintext.
	return plaintext, nil
}

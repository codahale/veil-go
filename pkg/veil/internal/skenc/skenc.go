// Package skenc provides the underlying STROBE protocols for Veil's authenticated secret key
// encryption.
//
// Encryption of a secret key is performed as follows, given a key K, a plaintext secret key R, and
// a tag size N:
//
//     INIT('veil.skenc', level=256)
//     AD(LE_U32(N)),     meta=true)
//     KEY(K)
//     SEND_ENC(R)
//     SEND_MAC(N)
//
// The ciphertext and T-byte tag are then returned.
//
// Decryption of a secret key is performed as follows, given a key K, a ciphertext C, an
// authentication tag T, and a tag size N:
//
//     INIT('veil.skenc', level=256)
//     AD(LE_U32(N)),     meta=true)
//     KEY(K)
//     RECV_ENC(C)
//     RECV_MAC(T)
//
// If the RECV_MAC operation is successful, the plaintext secret key is returned.
package skenc

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/sammyne/strobe"
)

// Encrypt encrypts the secret key with the key, appending a tag of the given size for
// authentication.
func Encrypt(key, secretKey []byte, tagSize int) []byte {
	ae := newAE("veil.skenc", key, tagSize)

	// Copy the plaintext to a buffer.
	ciphertext := make([]byte, len(secretKey), len(secretKey)+tagSize)
	copy(ciphertext, secretKey)

	// Encrypt it in place.
	internal.MustENC(ae.SendENC(ciphertext, &strobe.Options{}))

	// Create a MAC.
	tag := make([]byte, tagSize)
	internal.Must(ae.SendMAC(tag, &strobe.Options{}))

	// Return the ciphertext and tag.
	return append(ciphertext, tag...)
}

// Decrypt decrypts the encrypted secret key using the key, detaching and verifying the
// authentication tag of the given size.
func Decrypt(key, encSecretKey []byte, tagSize int) ([]byte, error) {
	ae := newAE("veil.skenc", key, tagSize)

	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(encSecretKey)-tagSize)
	copy(plaintext, encSecretKey[:len(encSecretKey)-tagSize])

	// Copy the tag.
	tag := make([]byte, tagSize)
	copy(tag, encSecretKey[len(encSecretKey)-tagSize:])

	// Decrypt it in place.
	internal.MustENC(ae.RecvENC(plaintext, &strobe.Options{}))

	// Verify the MAC.
	if err := ae.RecvMAC(tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the plaintext.
	return plaintext, nil
}

func newAE(protocol string, key []byte, tagSize int) *strobe.Strobe {
	// Create a new protocol.
	ae := internal.Strobe(protocol)

	// Add the tag size to the protocol.
	internal.Must(ae.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Initialize the protocol with the key.
	internal.Must(ae.KEY(internal.Copy(key), false))

	return ae
}

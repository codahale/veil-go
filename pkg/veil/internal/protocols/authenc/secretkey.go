package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

// EncryptSecretKey encrypts the secret key with the key, appending a tag of the given size for
// authentication.
func EncryptSecretKey(key, secretKey []byte, tagSize int) []byte {
	authenc := newProtocol(secretKeyProto, key, tagSize)

	// Copy the plaintext to a buffer.
	ciphertext := make([]byte, len(secretKey), len(secretKey)+tagSize)
	copy(ciphertext, secretKey)

	// Encrypt it in place.
	protocols.MustENC(authenc.SendENC(ciphertext, &strobe.Options{}))

	// Create a MAC.
	tag := make([]byte, tagSize)
	protocols.Must(authenc.SendMAC(tag, &strobe.Options{}))

	// Return the ciphertext and tag.
	return append(ciphertext, tag...)
}

// DecryptSecretKey decrypts the encrypted secret key using the key, detaching and verifying the
// authentication tag of the given size.
func DecryptSecretKey(key, encSecretKey []byte, tagSize int) ([]byte, error) {
	authenc := newProtocol(secretKeyProto, key, tagSize)

	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(encSecretKey)-tagSize)
	copy(plaintext, encSecretKey[:len(encSecretKey)-tagSize])

	// Copy the tag.
	tag := make([]byte, tagSize)
	copy(tag, encSecretKey[len(encSecretKey)-tagSize:])

	// Decrypt it in place.
	protocols.MustENC(authenc.RecvENC(plaintext, &strobe.Options{}))

	// Verify the MAC.
	if err := authenc.RecvMAC(tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the plaintext.
	return plaintext, nil
}

// Package authenc provides the underlying STROBE protocol for Veil's authentication encryption.
//
// Encryption and decryption are initialized as follows, given a protocol name P, a key K and and
// tag size T:
//
//     INIT(P,                level=256)
//     AD(BIG_ENDIAN_U32(T)), meta=true)
//     KEY(K,                 streaming=false)
//
// Encryption of a secret, S, is as follows:
//
//     SEND_ENC(S)
//     SEND_MAC(T)
//
// The ciphertext and T-byte tag are then returned.
//
// Decryption of a secret is the same as encryption with RECV_ENC and RECV_MAC in place of SEND_ENC
// and RECV_ENC, respectively. No plaintext is returned without a successful RECV_MAC call.
//
// The two recognized protocol identifiers are:
//
// * `veil.header`, used to encrypt message headers
// * `veil.secretkey`, used to encrypt secret keys
package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

//nolint:gosec // these are not secrets, dummy
const (
	KeySize        = 32                       // KeySize is the symmetric key size in bytes.
	TagSize        = 16                       // TagSize is the authentication tag size in bytes.
	headerProto    = "veil.authenc.header"    // Header is used to encrypt headers.
	secretKeyProto = "veil.authenc.secretkey" // SecretKey is used to encrypt secret keys.
)

// EncryptHeader encrypts the header with the key, appending a tag of the given size for
// authentication.
func EncryptHeader(key, header []byte, tagSize int) []byte {
	return encrypt(headerProto, key, header, tagSize)
}

// DecryptHeader decrypts the encrypted header using the key, detaching and verifying the
// authentication tag of the given size.
func DecryptHeader(key, encHeader []byte, tagSize int) ([]byte, error) {
	return decrypt(headerProto, key, encHeader, tagSize)
}

// EncryptHeader encrypts the secret key with the key, appending a tag of the given size for
// authentication.
func EncryptSecretKey(key, secretKey []byte, tagSize int) []byte {
	return encrypt(secretKeyProto, key, secretKey, tagSize)
}

// DecryptSecretKey decrypts the encrypted secret key using the key, detaching and verifying the
// authentication tag of the given size.
func DecryptSecretKey(key, encSecretKey []byte, tagSize int) ([]byte, error) {
	return decrypt(secretKeyProto, key, encSecretKey, tagSize)
}

// encrypt uses the protocol to encrypt the plaintext with the key, appending a tag of the given
// size for authentication.
func encrypt(protocol string, key, plaintext []byte, tagSize int) []byte {
	authenc := newProtocol(protocol, key, tagSize)

	// Copy the plaintext to a buffer.
	ciphertext := make([]byte, len(plaintext), len(plaintext)+tagSize)
	copy(ciphertext, plaintext)

	// Encrypt it in place.
	protocols.MustENC(authenc.SendENC(ciphertext, &strobe.Options{}))

	// Create a MAC.
	tag := make([]byte, tagSize)
	protocols.Must(authenc.SendMAC(tag, &strobe.Options{}))

	// Return the ciphertext and tag.
	return append(ciphertext, tag...)
}

// decrypt uses the protocol to decrypt the ciphertext using the key, detaching and verifying the
// authentication tag of the given size.
func decrypt(protocol string, key, ciphertext []byte, tagSize int) ([]byte, error) {
	authenc := newProtocol(protocol, key, tagSize)

	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(ciphertext)-tagSize)
	copy(plaintext, ciphertext[:len(ciphertext)-tagSize])

	// Copy the tag.
	tag := make([]byte, tagSize)
	copy(tag, ciphertext[len(ciphertext)-tagSize:])

	// Decrypt it in place.
	protocols.MustENC(authenc.RecvENC(plaintext, &strobe.Options{}))

	// Verify the MAC.
	if err := authenc.RecvMAC(tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the plaintext.
	return plaintext, nil
}

func newProtocol(protocol string, key []byte, tagSize int) *strobe.Strobe {
	// Create a new protocol.
	authenc := protocols.New(protocol)

	// Add the tag size to the protocol.
	protocols.Must(authenc.AD(protocols.BigEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Copy the key.
	k := make([]byte, len(key))
	copy(k, key)

	// Initialize the protocol with the key.
	protocols.Must(authenc.KEY(k, false))

	return authenc
}

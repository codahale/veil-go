// Package esk provides the underlying STROBE protocol for Veil's encryption of secret keys.
//
// Encryption and decryption are initialized as follows, given a key K and and tag size T:
//
//     INIT('veil.esk',       level=256)
//     AD(BIG_ENDIAN_U32(T)), meta=true, streaming=false)
//     KEY(K,                 streaming=false)
//
// Encryption of a serialized secret key, S, is as follows:
//
//     SEND_ENC(S, meta=false, streaming=false)
//     SEND_MAC(T, meta=false, streaming=false)
//
// The ciphertext and T-byte tag are then returned.
//
// Decryption of a secret key is the same as encryption with RECV_ENC and RECV_MAC in place of
// SEND_ENC and RECV_ENC, respectively. No plaintext is returned without a successful RECV_MAC call.
package esk

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

// Encrypt encrypts the given serialized secret key with the derived key, appending a tag of the
// given size for authentication.
func Encrypt(key, secretKey []byte, tagSize int) []byte {
	esk := newProtocol(key, tagSize)

	// Copy the secret key.
	sk := make([]byte, len(secretKey), len(secretKey)+tagSize)
	copy(sk, secretKey)

	// Encrypt it in place.
	if _, err := esk.SendENC(sk, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Create a MAC.
	tag := make([]byte, tagSize)
	if err := esk.SendMAC(tag, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Return the ciphertext and tag.
	return append(sk, tag...)
}

// Decrypt decrypts the given encrypted secret key using the derived key, detaching and verifying
// the authentication tag of the given size.
func Decrypt(key, encryptedSecretKey []byte, tagSize int) ([]byte, error) {
	esk := newProtocol(key, tagSize)

	// Copy the encrypted secret key.
	sk := make([]byte, len(encryptedSecretKey)-tagSize)
	copy(sk, encryptedSecretKey[:len(encryptedSecretKey)-tagSize])

	// Copy the tag.
	tag := make([]byte, tagSize)
	copy(tag, encryptedSecretKey[len(encryptedSecretKey)-tagSize:])

	// Decrypt it in place.
	if _, err := esk.RecvENC(sk, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Verify the MAC.
	if err := esk.RecvMAC(tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the plaintext.
	return sk, nil
}

func newProtocol(key []byte, tagSize int) *strobe.Strobe {
	// Create a new ESK protocol.
	esk, err := strobe.New("veil.esk", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	// Add the tag size to the protocol.
	if err := esk.AD(protocols.BigEndianU32(tagSize), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Copy the key.
	k := make([]byte, len(key))
	copy(k, key)

	// Initialize the protocol with the key.
	if err := esk.KEY(k, false); err != nil {
		panic(err)
	}

	return esk
}

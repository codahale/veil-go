package veil

import (
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	demKeyLen   = 32
	demNonceLen = 24
	demTagLen   = 16
	demOverhead = demNonceLen + demTagLen
)

// demEncrypt generates a random nonce, encrypts the plaintext with XChaCha20Poly1305 using the
// given authenticated data, and returns the nonce and ciphertext.
func demEncrypt(rand io.Reader, key, plaintext, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce.
	nonce := make([]byte, demNonceLen)
	_, err = io.ReadFull(rand, nonce)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, data), nil
}

// demDecrypt decrypts the given ciphertext with XChaCha20Poly1305.
func demDecrypt(key, ciphertext, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, ciphertext[:demNonceLen], ciphertext[demNonceLen:], data)
}

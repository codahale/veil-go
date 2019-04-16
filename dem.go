package veil

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	demKeyLen   = 32
	demNonceLen = 24
	demTagLen   = 16
	demOverhead = demNonceLen + demTagLen
)

func demEncrypt(key, plaintext, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, demNonceLen)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, data), nil
}

func demDecrypt(key, ciphertext, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:demNonceLen]
	ciphertext = ciphertext[demNonceLen:]
	return aead.Open(nil, nonce, ciphertext, data)
}

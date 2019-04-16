package veil

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	demKeyLen   = 32
	demNonceLen = 24
	demTagLen   = 32
	demOverhead = demNonceLen + demTagLen
)

func demEncrypt(key, plaintext, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce.
	nonce := make([]byte, demNonceLen)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// Seal with XChaCha20Poly1305, which appends 16-byte Poly1305 tag, and prepend the nonce.
	ciphertext := aead.Seal(nonce, nonce, plaintext, data)

	// Hash the Poly1305 tag with BLAKE2b.
	poly1305 := ciphertext[demNonceLen+len(plaintext):]
	tag := blake2b.Sum256(poly1305)

	// Return the nonce, the XChaCha20 ciphertext, and the hashed Poly1305 tag.
	return append(ciphertext[:demNonceLen+len(plaintext)], tag[:]...), nil
}

func demDecrypt(key, ciphertext, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:demNonceLen]
	tag := ciphertext[len(ciphertext)-demTagLen:]
	ciphertext = ciphertext[demNonceLen : len(ciphertext)-demTagLen]

	// This is some of the dumbest code I've written, but necessary b/c the Go crypto libs don't
	// expose either the underlying ChaCha20 primitives or the subkey generation code. Rather than
	// re-implement all of that myself, I'm cheating and using two AEAD#seal operations to a)
	// recover the XChaCha20 keystream and b) the expected Poly1305 hash.

	// First, recover the XChaCha20 keystream by encrypting a block of all zeros.
	stream := aead.Seal(nil, nonce, make([]byte, len(ciphertext)), data)

	// Second, recover the plaintext by XORing the ciphertext with the recovered keystream.
	plaintext := make([]byte, len(ciphertext))
	for i, v := range stream[:len(plaintext)] {
		plaintext[i] = ciphertext[i] ^ v
	}

	// Third, seal the recovered plaintext to produce the expected Poly1305 tag.
	poly1305 := aead.Seal(nil, nonce, plaintext, data)[len(plaintext):]

	// Fourth, hash the candidate with BLAKE2b.
	candidate := blake2b.Sum256(poly1305)

	// Finally, compare the recovered tag with the found tag.
	if subtle.ConstantTimeCompare(candidate[:], tag) == 0 {
		return nil, errors.New("invalid ciphertext")
	}
	return plaintext, nil
}

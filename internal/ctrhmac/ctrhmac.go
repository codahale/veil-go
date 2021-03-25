// Package ctrhmac implements a key-committing AEAD using AES-256-CTR and HMAC-SHA256.
//
// ctrhmac is a simple encrypt-then-MAC AEAD which encrypts plaintext using AES-256-CTR and appends
// a truncated HMAC-SHA256 of the IV, ciphertext, the ciphertext length, the authenticated data, and
// the authenticated data length using the same key. Both lengths are in bits and are formatted as
// 64-bit big-endian integers. The output of HMAC-SHA256 is truncated to 128 bits.
//
// In addition to protecting against partitioning oracle attacks, ctrhmac has strong guarantees that
// its output is indistinguishable from random noise. Both AES and HMAC output are uniformly
// distributed.
package ctrhmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

// ErrInvalidCiphertext is returned when a ciphertext cannot be decrypted, either due to an
// incorrect key or tampering.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

type ctrHMAC struct {
	block cipher.Block
	hmac  hash.Hash
}

const (
	KeySize  = 32            // The size of an AES-256 key.
	IVSize   = aes.BlockSize // The size of an AES-CTR IV.
	Overhead = 16            // The size of a truncated HMAC-SHA256 digest.
)

// New returns a new AES-256-CTR+HMAC-SHA256 AEAD using the given 256-bit key.
func New(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return &ctrHMAC{
		block: b,
		hmac:  hmac.New(sha256.New, key),
	}
}

func (h *ctrHMAC) NonceSize() int {
	return IVSize
}

func (h *ctrHMAC) Overhead() int {
	return Overhead
}

func (h *ctrHMAC) Seal(dst, iv, plaintext, additionalData []byte) []byte {
	// Create a buffer for the output.
	out := make([]byte, len(plaintext)+Overhead)

	// Encrypt the plaintext with AES-CTR.
	cipher.NewCTR(h.block, iv).XORKeyStream(out, plaintext)

	// Calculate the HMAC of the ciphertext and append it.
	out = h.hash(out[:len(plaintext)], out[:len(plaintext)], iv, additionalData)

	// Return the output appended to dst.
	return append(dst, out...)
}

func (h *ctrHMAC) Open(dst, iv, ciphertext, additionalData []byte) ([]byte, error) {
	// Separate the HMAC and the ciphertext.
	n := len(ciphertext) - h.Overhead()
	mac := ciphertext[n:]
	in := ciphertext[:n]
	out := make([]byte, len(in))

	// Verify the HMAC.
	if !hmac.Equal(mac, h.hash(nil, in, iv, additionalData)) {
		return nil, ErrInvalidCiphertext
	}

	// Decrypt the ciphertext with AES-CTR.
	cipher.NewCTR(h.block, iv).XORKeyStream(out, in)

	return append(dst, out...), nil
}

func (h *ctrHMAC) hash(dst, ciphertext, iv, data []byte) []byte {
	// Hash the IV.
	_, _ = h.hmac.Write(iv)

	// Hash the ciphertext.
	_, _ = h.hmac.Write(ciphertext)

	// Hash the additional data.
	_, _ = h.hmac.Write(data)

	// Write the lengths of the ciphertext and additional data in bits.
	_ = binary.Write(h.hmac, binary.BigEndian, uint64(len(ciphertext))*8)
	_ = binary.Write(h.hmac, binary.BigEndian, uint64(len(data))*8)

	// Calculate and truncate the digest.
	d := h.hmac.Sum(nil)[:Overhead]

	// Reset the HMAC for its next calculation.
	h.hmac.Reset()

	// Append the digest to dst and return.
	return append(dst, d...)
}

var _ cipher.AEAD = &ctrHMAC{}

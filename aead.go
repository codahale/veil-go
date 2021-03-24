package veil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

type aesCTRHMAC struct {
	aes  cipher.Block
	hmac hash.Hash
}

const (
	aeadIVSize   = aes.BlockSize
	aeadOverhead = sha512.Size256 // The size of an HMAC-SHA2-512/256 digest.
)

func newHMACAEAD(key []byte) cipher.AEAD {
	b, _ := aes.NewCipher(key)

	return &aesCTRHMAC{
		aes:  b,
		hmac: hmac.New(sha512.New512_256, key),
	}
}

func (h *aesCTRHMAC) NonceSize() int {
	return aeadIVSize
}

func (h *aesCTRHMAC) Overhead() int {
	return aeadOverhead
}

func (h *aesCTRHMAC) Seal(dst, iv, plaintext, additionalData []byte) []byte {
	// Create a buffer for the output.
	out := make([]byte, len(plaintext)+aeadOverhead)

	// Encrypt the plaintext with AES-CTR.
	cipher.NewCTR(h.aes, iv).XORKeyStream(out, plaintext)

	// Calculate the HMAC of the ciphertext and append it.
	out = h.hash(out[:len(plaintext)], out[:len(plaintext)], additionalData)

	// Return the output appended to dst.
	return append(dst, out...)
}

func (h *aesCTRHMAC) Open(dst, iv, ciphertext, additionalData []byte) ([]byte, error) {
	// Separate the HMAC and the ciphertext.
	n := len(ciphertext) - h.hmac.Size()
	mac := ciphertext[n:]
	in := ciphertext[:n]
	out := make([]byte, len(in))

	// Verify the HMAC.
	if !hmac.Equal(mac, h.hash(nil, in, additionalData)) {
		return nil, ErrInvalidCiphertext
	}

	// Decrypt the ciphertext with AES-CTR.
	cipher.NewCTR(h.aes, iv).XORKeyStream(out, in)

	return append(dst, out...), nil
}

func (h *aesCTRHMAC) hash(dst, ciphertext, data []byte) []byte {
	// Always reset the HMAC once the digest is calculated.
	defer h.hmac.Reset()

	// Hash the ciphertext.
	_, _ = h.hmac.Write(ciphertext)

	// Hash the additional data.
	_, _ = h.hmac.Write(data)

	// Write the lengths of the ciphertext and additional data in bits.
	_ = binary.Write(h.hmac, binary.BigEndian, uint64(len(ciphertext))*8)
	_ = binary.Write(h.hmac, binary.BigEndian, uint64(len(data))*8)

	// Append the digest to dst and return.
	return h.hmac.Sum(dst)
}

var _ cipher.AEAD = &aesCTRHMAC{}

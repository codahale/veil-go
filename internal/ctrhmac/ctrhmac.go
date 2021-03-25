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

type aesSHA256 struct {
	aes  cipher.Block
	hmac hash.Hash
}

const (
	KeySize  = 32            // The size of an AES-256 key.
	IVSize   = aes.BlockSize // The size of an AES-CTR IV.
	Overhead = sha256.Size   // The size of an HMAC-SHA2-256 digest.
)

func New(key []byte) cipher.AEAD {
	b, _ := aes.NewCipher(key)

	return &aesSHA256{
		aes:  b,
		hmac: hmac.New(sha256.New, key),
	}
}

func (h *aesSHA256) NonceSize() int {
	return IVSize
}

func (h *aesSHA256) Overhead() int {
	return Overhead
}

func (h *aesSHA256) Seal(dst, iv, plaintext, additionalData []byte) []byte {
	// Create a buffer for the output.
	out := make([]byte, len(plaintext)+Overhead)

	// Encrypt the plaintext with AES-CTR.
	cipher.NewCTR(h.aes, iv).XORKeyStream(out, plaintext)

	// Calculate the HMAC of the ciphertext and append it.
	out = h.hash(out[:len(plaintext)], out[:len(plaintext)], iv, additionalData)

	// Return the output appended to dst.
	return append(dst, out...)
}

func (h *aesSHA256) Open(dst, iv, ciphertext, additionalData []byte) ([]byte, error) {
	// Separate the HMAC and the ciphertext.
	n := len(ciphertext) - h.hmac.Size()
	mac := ciphertext[n:]
	in := ciphertext[:n]
	out := make([]byte, len(in))

	// Verify the HMAC.
	if !hmac.Equal(mac, h.hash(nil, in, iv, additionalData)) {
		return nil, ErrInvalidCiphertext
	}

	// Decrypt the ciphertext with AES-CTR.
	cipher.NewCTR(h.aes, iv).XORKeyStream(out, in)

	return append(dst, out...), nil
}

func (h *aesSHA256) hash(dst, ciphertext, iv, data []byte) []byte {
	// Always reset the HMAC once the digest is calculated.
	defer h.hmac.Reset()

	// Hash the IV.
	_, _ = h.hmac.Write(iv)

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

var _ cipher.AEAD = &aesSHA256{}

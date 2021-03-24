package veil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"hash"
)

// hmacAEAD adds key-commitment to a existing AEAD construction by calculating an HMAC of its output
// using the same key as for encryption. This guarantees that the ciphertext was created with the
// same key as was used to decrypt it.
type hmacAEAD struct {
	aead cipher.AEAD
	hmac hash.Hash
}

const (
	gcmNonceSize    = 12      // The size of a GCM nonce.
	gcmHMACOverhead = 16 + 32 // The size of a GCM tag plus an HMAC-SHA2-512/256 digest.
)

// newHMACAEAD returns an AEAD which combines AES-256-GCM with HMAC-SHA2-512/256.
func newHMACAEAD(key []byte) cipher.AEAD {
	b, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(b)

	return &hmacAEAD{
		aead: gcm,
		hmac: hmac.New(sha512.New512_256, key),
	}
}

func (h *hmacAEAD) NonceSize() int {
	return h.aead.NonceSize()
}

func (h *hmacAEAD) Overhead() int {
	return h.aead.Overhead() + h.hmac.Size()
}

func (h *hmacAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	// Create a buffer for the output.
	out := make([]byte, 0, len(plaintext)+h.Overhead())

	// Encrypt the plaintext with the underlying AEAD.
	out = h.aead.Seal(out, nonce, plaintext, additionalData)

	// Calculate the HMAC of the ciphertext and append it.
	out = h.hash(out, out)

	// Return the output appended to dst.
	return append(dst, out...)
}

func (h *hmacAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	// Separate the HMAC and the ciphertext.
	n := len(ciphertext) - h.hmac.Size()
	mac := ciphertext[n:]
	c := ciphertext[:n]

	// Verify the HMAC.
	if !hmac.Equal(mac, h.hash(nil, c)) {
		return nil, ErrInvalidCiphertext
	}

	// Decrypt the ciphertext using the underlying AEAD.
	return h.aead.Open(dst, nonce, c, additionalData)
}

func (h *hmacAEAD) hash(dst, c []byte) []byte {
	// Always reset the HMAC once the digest is calculated.
	defer h.hmac.Reset()

	// Hash the ciphertext.
	_, _ = h.hmac.Write(c)

	// Append the digest to dst and return.
	return h.hmac.Sum(dst)
}

var _ cipher.AEAD = &hmacAEAD{}

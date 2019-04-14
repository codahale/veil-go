package veil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
)

const demOverhead = 32 + 16

func demEncrypt(key, plaintext, data []byte) ([]byte, error) {
	c, h, err := subkeys(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext)+16)

	// generate random nonce
	_, err = io.ReadFull(rand.Reader, ciphertext[:16])
	if err != nil {
		return nil, err
	}

	// encrypt plaintext with AES-128-CTR
	cipher.NewCTR(c, ciphertext[:16]).XORKeyStream(ciphertext[16:], plaintext)

	// return nonce + ciphertext + tag
	return appendTag(ciphertext, h, ciphertext, data), nil
}

func demDecrypt(key, ciphertext, data []byte) ([]byte, error) {
	c, h, err := subkeys(key)
	if err != nil {
		return nil, err
	}

	// check tag
	tagIdx := len(ciphertext) - 32
	tag := appendTag(nil, h, ciphertext[:tagIdx], data)
	if subtle.ConstantTimeCompare(tag, ciphertext[tagIdx:]) == 0 {
		return nil, errors.New("invalid ciphertext")
	}

	// decrypt with AES-128-CTR
	plaintext := make([]byte, len(ciphertext)-demOverhead)
	cipher.NewCTR(c, ciphertext[:16]).XORKeyStream(plaintext, ciphertext[16:tagIdx])
	return plaintext, nil
}

func appendTag(dst []byte, h hash.Hash, ciphertext, data []byte) []byte {
	h.Write(ciphertext)
	h.Write(data)
	_ = binary.Write(h, binary.BigEndian, uint64(len(data))*8)
	return h.Sum(dst)
}

func subkeys(key []byte) (cipher.Block, hash.Hash, error) {
	c, err := aes.NewCipher(key[0:16])
	if err != nil {
		return nil, nil, err
	}
	return c, hmac.New(sha512.New512_256, key[16:32]), nil
}

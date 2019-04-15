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

const (
	demKeyLen   = 32
	demNonceLen = 16
	demTagLen   = 32
	demOverhead = demNonceLen + demTagLen
)

func demEncrypt(key, plaintext, data []byte) ([]byte, error) {
	c, h, err := subkeys(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext)+demNonceLen)

	// generate random nonce
	_, err = io.ReadFull(rand.Reader, ciphertext[:demNonceLen])
	if err != nil {
		return nil, err
	}

	// encrypt plaintext with AES-128-CTR
	cipher.NewCTR(c, ciphertext[:demNonceLen]).XORKeyStream(ciphertext[demNonceLen:], plaintext)

	// return nonce + ciphertext + tag
	return appendTag(ciphertext, h, ciphertext, data), nil
}

func demDecrypt(key, ciphertext, data []byte) ([]byte, error) {
	c, h, err := subkeys(key)
	if err != nil {
		return nil, err
	}

	// check tag
	tagIdx := len(ciphertext) - demTagLen
	tag := appendTag(nil, h, ciphertext[:tagIdx], data)
	if subtle.ConstantTimeCompare(tag, ciphertext[tagIdx:]) == 0 {
		return nil, errors.New("invalid ciphertext")
	}

	// decrypt with AES-128-CTR
	plaintext := make([]byte, len(ciphertext)-demOverhead)
	ctr := cipher.NewCTR(c, ciphertext[:demNonceLen])
	ctr.XORKeyStream(plaintext, ciphertext[demNonceLen:tagIdx])
	return plaintext, nil
}

func appendTag(dst []byte, h hash.Hash, ciphertext, data []byte) []byte {
	h.Write(ciphertext)
	h.Write(data)
	_ = binary.Write(h, binary.BigEndian, uint64(len(data))*8)
	return h.Sum(dst)
}

func subkeys(key []byte) (cipher.Block, hash.Hash, error) {
	c, err := aes.NewCipher(key[0 : demKeyLen/2])
	if err != nil {
		return nil, nil, err
	}
	return c, hmac.New(sha512.New512_256, key[demKeyLen/2:demKeyLen]), nil
}

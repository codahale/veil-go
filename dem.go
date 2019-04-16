package veil

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/salsa20"
)

const (
	demKeyLen   = 64
	demNonceLen = 24
	demTagLen   = 32
	demOverhead = demNonceLen + demTagLen
)

func demEncrypt(key, plaintext, data []byte) ([]byte, error) {
	k, h := subkeys(key)
	ciphertext := make([]byte, len(plaintext)+demNonceLen)

	// generate random nonce
	_, err := io.ReadFull(rand.Reader, ciphertext[:demNonceLen])
	if err != nil {
		return nil, err
	}

	// encrypt with XSalsa20
	salsa20.XORKeyStream(ciphertext[demNonceLen:], plaintext, ciphertext[:demNonceLen], &k)

	// return nonce + ciphertext + tag
	return appendTag(ciphertext, h, ciphertext, data), nil
}

func demDecrypt(key, ciphertext, data []byte) ([]byte, error) {
	k, h := subkeys(key)

	// check tag
	tagIdx := len(ciphertext) - demTagLen
	tag := appendTag(nil, h, ciphertext[:tagIdx], data)
	if subtle.ConstantTimeCompare(tag, ciphertext[tagIdx:]) == 0 {
		return nil, errors.New("invalid ciphertext")
	}

	// decrypt with XSalsa20
	plaintext := make([]byte, len(ciphertext)-demOverhead)
	salsa20.XORKeyStream(plaintext, ciphertext[demNonceLen:tagIdx], ciphertext[:demNonceLen], &k)
	return plaintext, nil
}

func appendTag(dst []byte, h hash.Hash, ciphertext, data []byte) []byte {
	_, _ = h.Write(ciphertext)
	_, _ = h.Write(data)
	_ = binary.Write(h, binary.BigEndian, uint64(len(data))*8)
	_ = binary.Write(h, binary.BigEndian, uint64(len(ciphertext))*8)
	return h.Sum(dst)
}

func subkeys(key []byte) ([32]byte, hash.Hash) {
	var salsaKey [32]byte
	copy(salsaKey[:], key[:demKeyLen/2])
	return salsaKey, hmac.New(sha512.New512_256, key[demKeyLen/2:])
}

package veil

import (
	"encoding/binary"
	"io"
	"math"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptedKeyPair is a SecretKey that has been encrypted with a password.
type EncryptedKeyPair struct {
	Salt         []byte
	Ciphertext   []byte
	Time, Memory uint32
	Threads      uint8
}

const (
	defaultTime   = 1
	defaultMemory = 64 * 1024
)

// NewEncryptedKeyPair encrypts the given key pair with the given password.
func NewEncryptedKeyPair(rand io.Reader, sk SecretKey, password []byte) (*EncryptedKeyPair, error) {
	salt := make([]byte, 32)

	// Generate a random salt.
	_, err := io.ReadFull(rand, salt)
	if err != nil {
		return nil, err
	}

	// Use all available CPUs.
	threads := uint8(math.MaxUint8)
	if n := runtime.NumCPU(); n <= math.MaxUint8 {
		threads = uint8(n)
	}

	// Use Argon2id to derive a key and nonce from the password and salt.
	k := argon2.IDKey(password, salt, defaultTime, defaultMemory, threads, kdfOutputLen)

	// Encode the Argon2id parameters as authenticated data.
	data := encodeArgonParams(defaultTime, defaultMemory, threads)

	// Encrypt the secret key.
	aead, _ := chacha20poly1305.New(k[:chacha20poly1305.KeySize])
	ciphertext := aead.Seal(nil, k[chacha20poly1305.KeySize:], sk, data)

	// Return the salt, ciphertext, and parameters.
	return &EncryptedKeyPair{
		Salt:       salt,
		Ciphertext: ciphertext,
		Time:       defaultTime,
		Memory:     defaultMemory,
		Threads:    threads,
	}, nil
}

// Decrypt uses the given password to decrypt the key pair. Returns an error if the password is
// incorrect or if the encrypted key pair has been modified.
func (ekp *EncryptedKeyPair) Decrypt(password []byte) (SecretKey, error) {
	// Use Argon2id to derive a key and nonce from the password and salt.
	k := argon2.IDKey(password, ekp.Salt, ekp.Time, ekp.Memory, ekp.Threads, kdfOutputLen)

	// Encode the Argon parameters as authenticated data.
	data := encodeArgonParams(ekp.Time, ekp.Memory, ekp.Threads)

	aead, _ := chacha20poly1305.New(k[:chacha20poly1305.KeySize])

	// Decrypt the secret key.
	sk, err := aead.Open(nil, k[chacha20poly1305.KeySize:], ekp.Ciphertext, data)
	if err != nil {
		return nil, err
	}

	return sk, err
}

// encodeArgonParams returns the Argon2id params encoded as big-endian integers.
func encodeArgonParams(time, memory uint32, threads uint8) []byte {
	data := make([]byte, 9)
	binary.BigEndian.PutUint32(data, time)
	binary.BigEndian.PutUint32(data[4:], memory)
	data[8] = threads

	return data
}

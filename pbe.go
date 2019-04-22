package veil

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/scrypt"
)

// EncryptedKeyPair is a KeyPair that has been encrypted with a password.
type EncryptedKeyPair struct {
	Salt       []byte
	Ciphertext []byte
	N, R, P    int
}

const (
	defaultN = 32768
	defaultR = 8
	defaultP = 1
)

// NewEncryptedKeyPair encrypts the given key pair with the given password.
func NewEncryptedKeyPair(rand io.Reader, kp *KeyPair, password []byte) (*EncryptedKeyPair, error) {
	// Generate a random salt.
	salt := make([]byte, 32)
	_, err := io.ReadFull(rand, salt)
	if err != nil {
		return nil, err
	}

	// Encode the scrypt parameters as authenticated data.
	data := make([]byte, 12)
	binary.BigEndian.PutUint32(data, defaultN)
	binary.BigEndian.PutUint32(data[4:], defaultR)
	binary.BigEndian.PutUint32(data[8:], defaultP)

	// Use scrypt to derive a key and nonce from the password and salt.
	k, _ := scrypt.Key(password, salt, defaultN, defaultR, defaultP, chacha20poly1305.KeySize+chacha20poly1305.NonceSize)

	// Encrypt the secret key.
	aead, _ := chacha20poly1305.New(k[:chacha20poly1305.KeySize])
	ciphertext := aead.Seal(nil, k[chacha20poly1305.KeySize:], kp.SecretKey, data)

	// Return the salt, ciphertext, and parameters.
	return &EncryptedKeyPair{
		Salt:       salt,
		Ciphertext: ciphertext,
		N:          defaultN,
		R:          defaultR,
		P:          defaultP,
	}, nil
}

// Decrypt uses the given password to decrypt the key pair. Returns an error if the password is
// incorrect or if the encrypted key pair has been modified.
func (ekp *EncryptedKeyPair) Decrypt(password []byte) (*KeyPair, error) {
	// Use the password, salt, and parameters to derive a key and nonce.
	k, _ := scrypt.Key(password, ekp.Salt, ekp.N, ekp.R, ekp.P, chacha20poly1305.KeySize+chacha20poly1305.NonceSize)

	// Encode the scrypt parameters as authenticated data.
	data := make([]byte, 12)
	binary.BigEndian.PutUint32(data, uint32(ekp.N))
	binary.BigEndian.PutUint32(data[4:], uint32(ekp.R))
	binary.BigEndian.PutUint32(data[8:], uint32(ekp.P))

	// Decrypt the secret key.
	aead, _ := chacha20poly1305.New(k[:chacha20poly1305.KeySize])
	sk, err := aead.Open(nil, k[chacha20poly1305.KeySize:], ekp.Ciphertext, data)
	if err != nil {
		return nil, err
	}

	// Calculate the public key for the decrypted secret key.
	var dst, in [32]byte
	copy(in[:], sk)
	curve25519.ScalarBaseMult(&dst, &in)

	// Return a KeyPair.
	return &KeyPair{PublicKey: dst[:], SecretKey: sk}, nil
}

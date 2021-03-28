package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Argon2idParams contains the parameters of the Argon2id passphrase-based KDF algorithm.
type Argon2idParams struct {
	Time, Memory uint32 // The time and memory Argon2id parameters.
	Parallelism  uint8  // The parallelism Argon2id parameter.
}

// EncryptSecretKey encrypts the given secret key with the given passphrase and optional Argon2id
// parameters. Returns the encrypted key.
func EncryptSecretKey(sk SecretKey, passphrase []byte, params *Argon2idParams) ([]byte, error) {
	// Use default parameters if none are provided.
	if params == nil {
		// As recommended in https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-7.4.
		params = &Argon2idParams{
			Time:        1,
			Memory:      1 * 1024 * 1024, // 1GiB
			Parallelism: 4,
		}
	}

	// Generate a random salt.
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Use Argon2id to derive a key and nonce from the passphrase and salt.
	key, nonce := pbeKDF(passphrase, salt, params)

	// Initialize a ChaCha20Poly1305 AEAD.
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	// Encrypt the secret key.
	ciphertext := aead.Seal(nil, nonce, sk, nil)

	// Encode the Argon2id params, the salt, and the ciphertext.
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.BigEndian, params.Time)
	_ = binary.Write(buf, binary.BigEndian, params.Memory)
	_ = binary.Write(buf, binary.BigEndian, params.Parallelism)
	_, _ = buf.Write(salt)
	_, _ = buf.Write(ciphertext)

	return buf.Bytes(), err
}

// DecryptSecretKey decrypts the given secret key with the given passphrase. Returns the decrypted
// secret key.
func DecryptSecretKey(sk, passphrase []byte) (SecretKey, error) {
	var params Argon2idParams

	// Decode the Argon2id params, the salt, and the ciphertext.
	buf := bytes.NewReader(sk)
	_ = binary.Read(buf, binary.BigEndian, &params.Time)
	_ = binary.Read(buf, binary.BigEndian, &params.Memory)
	_ = binary.Read(buf, binary.BigEndian, &params.Parallelism)
	salt := sk[paramPrefixSize : paramPrefixSize+saltSize]
	ciphertext := sk[paramPrefixSize+saltSize:]

	// Use Argon2id to re-derive the key and nonce from the passphrase and salt.
	key, nonce := pbeKDF(passphrase, salt, &params)

	// Initialize a ChaCha20Poly1305 AEAD.
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	// Decrypt the secret key.
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)

	// Return it or any error in decryption.
	return plaintext, err
}

// pbeKDF uses Argon2id to derive a ChaCha20Poly1305 key and nonce from the passphrase, salt, and
// parameters.
func pbeKDF(passphrase, salt []byte, params *Argon2idParams) ([]byte, []byte) {
	kn := argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Parallelism,
		chacha20.KeySize+chacha20.NonceSize)

	return kn[:chacha20.KeySize], kn[chacha20.KeySize:]
}

const (
	saltSize        = 16
	paramPrefixSize = 1 + 4 + 4
)

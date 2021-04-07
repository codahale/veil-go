package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/authenc"
	"github.com/codahale/veil/pkg/veil/internal/balloonkdf"
)

// PBEParams contains the parameters of the passphrase-based KDF.
type PBEParams struct {
	Time, Space uint32 // The time and space parameters.
}

// EncryptSecretKey encrypts the given secret key with the given passphrase and optional PBE
// parameters. Returns the encrypted key.
func EncryptSecretKey(sk *SecretKey, passphrase []byte, params *PBEParams) ([]byte, error) {
	var encSK encryptedSecretKey

	// Use default parameters if none are provided.
	if params == nil {
		encSK.Params = PBEParams{
			Time:  64,
			Space: 1024,
		}
	} else {
		encSK.Params = *params
	}

	// Generate a random salt.
	if _, err := rand.Read(encSK.Salt[:]); err != nil {
		return nil, err
	}

	// Use balloon hashing to derive a key from the passphrase and salt.
	key := balloonkdf.DeriveKey(passphrase, encSK.Salt[:],
		int(encSK.Params.Space), int(encSK.Params.Time), internal.KeySize)

	// Encrypt the secret key.
	copy(encSK.Ciphertext[:], authenc.EncryptSecretKey(key, sk.r[:], internal.TagSize))

	// Encode the balloon hashing params, the salt, and the ciphertext.
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.LittleEndian, &encSK); err != nil {
		panic(err)
	}

	return buf.Bytes(), nil
}

// DecryptSecretKey decrypts the given secret key with the given passphrase. Returns the decrypted
// secret key.
func DecryptSecretKey(ciphertext, passphrase []byte) (*SecretKey, error) {
	var (
		encSK encryptedSecretKey
		sk    SecretKey
	)

	// Decode the encrypted secret key.
	if err := binary.Read(bytes.NewReader(ciphertext), binary.LittleEndian, &encSK); err != nil {
		return nil, err
	}

	// Use balloon hashing to re-derive the key from the passphrase and salt.
	key := balloonkdf.DeriveKey(passphrase, encSK.Salt[:],
		int(encSK.Params.Space), int(encSK.Params.Time), internal.KeySize)

	// Decrypt the encrypted secret key.
	plaintext, err := authenc.DecryptSecretKey(key, encSK.Ciphertext[:], internal.TagSize)
	if err != nil {
		return nil, err
	}

	// Copy it and return it.
	copy(sk.r[:], plaintext)

	return &sk, err
}

// encryptedSecretKey is a fixed-size struct of the encoded values for an encrypted secret key.
type encryptedSecretKey struct {
	Params     PBEParams
	Salt       [saltSize]byte
	Ciphertext [ciphertextSize]byte
}

const (
	saltSize       = 32
	ciphertextSize = internal.UniformBytestringSize + internal.TagSize
)

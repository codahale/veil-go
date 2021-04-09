package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/pbenc"
)

// PBEParams contains the parameters of the passphrase-based KDF.
type PBEParams struct {
	Time, Space uint32 // The time and space parameters.
}

// Encrypt encrypts the secret key with the given passphrase and optional PBE parameters. Returns
// the encrypted key.
func (sk *SecretKey) Encrypt(passphrase []byte, params *PBEParams) ([]byte, error) {
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

	// Encrypt the secret key.
	copy(encSK.Ciphertext[:],
		pbenc.Encrypt(
			passphrase, encSK.Salt[:], sk.r[:],
			int(encSK.Params.Space), int(encSK.Params.Time), internal.PBEBlockSize, internal.TagSize,
		))

	// Encode the balloon hashing params, the salt, and the ciphertext.
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.LittleEndian, &encSK); err != nil {
		panic(err)
	}

	return buf.Bytes(), nil
}

// DecryptSecretKey decrypts the given secret key with the given passphrase. Returns the decrypted
// secret key.
func DecryptSecretKey(passphrase, ciphertext []byte) (*SecretKey, error) {
	var (
		encSK encryptedSecretKey
		sk    SecretKey
	)

	// Decode the encrypted secret key.
	if err := binary.Read(bytes.NewReader(ciphertext), binary.LittleEndian, &encSK); err != nil {
		return nil, err
	}

	// Decrypt the encrypted secret key.
	plaintext, err := pbenc.Decrypt(
		passphrase, encSK.Salt[:], encSK.Ciphertext[:],
		int(encSK.Params.Space), int(encSK.Params.Time), internal.PBEBlockSize, internal.TagSize,
	)
	if err != nil {
		return nil, ErrInvalidCiphertext
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

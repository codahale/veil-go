package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal/protocols/authenc"
	"github.com/codahale/veil/pkg/veil/internal/protocols/balloon"
	"github.com/codahale/veil/pkg/veil/internal/r255"
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
	key := balloon.Hash(passphrase, encSK.Salt[:], encSK.Params.Space, encSK.Params.Time, authenc.KeySize)

	// Encrypt the secret key.
	copy(encSK.Ciphertext[:], authenc.EncryptSecretKey(key, sk.k.Encode(nil), authenc.TagSize))

	// Encode the balloon hashing params, the salt, and the ciphertext.
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, &encSK); err != nil {
		panic(err)
	}

	return buf.Bytes(), nil
}

// DecryptSecretKey decrypts the given secret key with the given passphrase. Returns the decrypted
// secret key.
func DecryptSecretKey(sk, passphrase []byte) (*SecretKey, error) {
	// Decode the encrypted secret key.
	var encSK encryptedSecretKey
	if err := binary.Read(bytes.NewReader(sk), binary.BigEndian, &encSK); err != nil {
		return nil, err
	}

	// Use balloon hashing to re-derive the key from the passphrase and salt.
	key := balloon.Hash(passphrase, encSK.Salt[:], encSK.Params.Space, encSK.Params.Time, authenc.KeySize)

	// Decrypt the encrypted secret key.
	plaintext, err := authenc.DecryptSecretKey(key, encSK.Ciphertext[:], authenc.TagSize)
	if err != nil {
		return nil, err
	}

	// Decode the secret key.
	dsk, err := r255.DecodeSecretKey(plaintext)
	if err != nil {
		return nil, err
	}

	// Return it.
	return &SecretKey{k: dsk}, nil
}

// encryptedSecretKey is a fixed-size struct of the encoded values for an encrypted secret key.
type encryptedSecretKey struct {
	Params     PBEParams
	Salt       [saltSize]byte
	Ciphertext [ciphertextSize]byte
}

const (
	saltSize       = 32
	ciphertextSize = r255.SecretKeySize + authenc.TagSize
)

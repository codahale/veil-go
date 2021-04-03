package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal/protocols/authenc"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"golang.org/x/crypto/argon2"
)

// Argon2idParams contains the parameters of the Argon2id passphrase-based KDF algorithm.
type Argon2idParams struct {
	Time, Memory uint32 // The time and memory Argon2id parameters.
	Parallelism  uint8  // The parallelism Argon2id parameter.
}

// EncryptSecretKey encrypts the given secret key with the given passphrase and optional Argon2id
// parameters. Returns the encrypted key.
func EncryptSecretKey(sk *SecretKey, passphrase []byte, params *Argon2idParams) ([]byte, error) {
	var encSK encryptedSecretKey

	// Use default parameters if none are provided.
	if params == nil {
		// As recommended in https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-7.4.
		encSK.Params = Argon2idParams{
			Time:        1,
			Memory:      1 * 1024 * 1024, // 1GiB
			Parallelism: 4,
		}
	} else {
		encSK.Params = *params
	}

	// Generate a random salt.
	if _, err := rand.Read(encSK.Salt[:]); err != nil {
		return nil, err
	}

	// Use Argon2id to derive a key from the passphrase and salt.
	key := pbeKDF(passphrase, encSK.Salt[:], &encSK.Params)

	// Encrypt the secret key.
	copy(encSK.Ciphertext[:], authenc.EncryptSecretKey(key, sk.k.Encode(nil), authenc.TagSize))

	// Encode the Argon2id params, the salt, and the ciphertext.
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

	// Use Argon2id to re-derive the key from the passphrase and salt.
	key := pbeKDF(passphrase, encSK.Salt[:], &encSK.Params)

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
	Params     Argon2idParams
	Salt       [saltSize]byte
	Ciphertext [ciphertextSize]byte
}

// pbeKDF uses Argon2id to derive a symmetric key and nonce from the passphrase, salt, and
// parameters.
func pbeKDF(passphrase, salt []byte, params *Argon2idParams) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Parallelism, authenc.KeySize)
}

const (
	saltSize       = 16 // per https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-3.1
	ciphertextSize = r255.SecretKeySize + authenc.TagSize
)

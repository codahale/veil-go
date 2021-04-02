package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"github.com/codahale/veil/internal/r255"
	"github.com/codahale/veil/internal/sym"
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
	var esk encryptedSecretKey

	// Use default parameters if none are provided.
	if params == nil {
		// As recommended in https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-7.4.
		esk.Params = Argon2idParams{
			Time:        1,
			Memory:      1 * 1024 * 1024, // 1GiB
			Parallelism: 4,
		}
	} else {
		esk.Params = *params
	}

	// Generate a random salt.
	if _, err := rand.Read(esk.Salt[:]); err != nil {
		return nil, err
	}

	// Use Argon2id to derive a key and nonce from the passphrase and salt.
	key, nonce := pbeKDF(passphrase, esk.Salt[:], &esk.Params)

	// Initialize an AEAD.
	aead, err := sym.NewAEAD(key)
	if err != nil {
		panic(err)
	}

	// Encrypt the secret key.
	copy(esk.Ciphertext[:], aead.Seal(esk.Ciphertext[:0], nonce, sk.k.Encode(nil), nil))

	// Encode the Argon2id params, the salt, and the ciphertext.
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, &esk); err != nil {
		panic(err)
	}

	return buf.Bytes(), nil
}

// DecryptSecretKey decrypts the given secret key with the given passphrase. Returns the decrypted
// secret key.
func DecryptSecretKey(sk, passphrase []byte) (*SecretKey, error) {
	// Decode the encrypted secret key.
	var esk encryptedSecretKey
	if err := binary.Read(bytes.NewReader(sk), binary.BigEndian, &esk); err != nil {
		return nil, err
	}

	// Use Argon2id to re-derive the key and nonce from the passphrase and salt.
	key, nonce := pbeKDF(passphrase, esk.Salt[:], &esk.Params)

	// Initialize an AEAD.
	aead, err := sym.NewAEAD(key)
	if err != nil {
		panic(err)
	}

	// Decrypt the secret key.
	plaintext, err := aead.Open(nil, nonce, esk.Ciphertext[:], nil)
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
func pbeKDF(passphrase, salt []byte, params *Argon2idParams) ([]byte, []byte) {
	kn := argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Parallelism,
		sym.KeySize+sym.NonceSize)

	return kn[:sym.KeySize], kn[sym.KeySize:]
}

const (
	saltSize       = 16 // per https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-3.1
	ciphertextSize = r255.SecretKeySize + sym.TagSize
)

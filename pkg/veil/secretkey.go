package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/codahale/veil/pkg/veil/internal/pbenc"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/scaldf"
	"github.com/gtank/ristretto255"
)

// PBEParams contains the parameters of the passphrase-based KDF.
type PBEParams struct {
	Time, Space uint32 // The time and space parameters.
}

// SecretKey is a key that's used to derive PrivateKey instances (and thus PublicKey instances).
//
// It should never be serialized in plaintext. Use EncryptSecretKey to encrypt it using a
// passphrase.
type SecretKey struct {
	r [internal.UniformBytestringSize]byte
}

// NewSecretKey creates a new secret key.
func NewSecretKey() (*SecretKey, error) {
	var sk SecretKey

	// Generate a random 64-byte key.
	if _, err := rand.Read(sk.r[:]); err != nil {
		return nil, err
	}

	return &sk, nil
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
		passphrase, encSK.Salt[:], encSK.Ciphertext[:], int(encSK.Params.Space), int(encSK.Params.Time))
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	// Copy it and return it.
	copy(sk.r[:], plaintext)

	return &sk, err
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
	copy(encSK.Ciphertext[:], pbenc.Encrypt(
		passphrase, encSK.Salt[:], sk.r[:], int(encSK.Params.Space), int(encSK.Params.Time)))

	// Encode the balloon hashing params, the salt, and the ciphertext.
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.LittleEndian, &encSK); err != nil {
		panic(err)
	}

	return buf.Bytes(), nil
}

// PrivateKey returns a private key for the given key ID.
func (sk *SecretKey) PrivateKey(keyID string) *PrivateKey {
	return sk.root().Derive(keyID)
}

// PublicKey returns a public key for the given key ID.
func (sk *SecretKey) PublicKey(keyID string) *PublicKey {
	return sk.PrivateKey(keyID).PublicKey()
}

// String returns a safe identifier for the key.
func (sk *SecretKey) String() string {
	return sk.root().PublicKey().String()
}

// root returns the root private key, derived from the secret key using veil.scaldf.secret-key.
func (sk *SecretKey) root() *PrivateKey {
	d := scaldf.RootScalar(&sk.r)
	q := ristretto255.NewElement().ScalarBaseMult(d)

	return &PrivateKey{d: d, q: q}
}

var _ fmt.Stringer = &SecretKey{}

// encryptedSecretKey is a fixed-size struct of the encoded values for an encrypted secret key.
type encryptedSecretKey struct {
	Params     PBEParams
	Salt       [saltSize]byte
	Ciphertext [ciphertextSize]byte
}

const (
	saltSize       = 32
	ciphertextSize = internal.UniformBytestringSize + pbenc.Overhead
)

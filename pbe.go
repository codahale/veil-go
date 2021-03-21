package veil

import (
	"crypto/rand"
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
)

type Argon2idParams struct {
	Time, Memory uint32 // The time and memory Argon2id parameters.
	Parallelism  uint8  // The parallelism Argon2id parameter.
}

func (a *Argon2idParams) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)

	// Encode all params as fixed integers.
	b.AddUint32(a.Time)
	b.AddUint32(a.Memory)
	b.AddUint8(a.Parallelism)

	return b.Bytes()
}

// ErrInvalidArgon2idParams is returned when an Argon2idParams cannot be unmarshalled from the
// provided data.
var ErrInvalidArgon2idParams = errors.New("invalid Argon2id params")

func (a *Argon2idParams) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)

	// Decode all params.
	if !(s.ReadUint32(&a.Time) && s.ReadUint32(&a.Memory) && s.ReadUint8(&a.Parallelism)) {
		return ErrInvalidArgon2idParams
	}

	return nil
}

var (
	_ encoding.BinaryMarshaler   = &Argon2idParams{}
	_ encoding.BinaryUnmarshaler = &Argon2idParams{}
)

// EncryptedSecretKey is a SecretKey that has been encrypted with a password.
type EncryptedSecretKey struct {
	Argon2idParams
	Salt       []byte // The random salt used to encrypt the secret key.
	Ciphertext []byte // The secret key, encrypted with ChaCha20Poly1305.
}

func (esk *EncryptedSecretKey) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)

	// Encode the salt with an 8-bit length prefix.
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(esk.Salt)
	})

	// Encode the ciphertext with a 16-bit length prefix.
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(esk.Ciphertext)
	})

	// Encode the Argon2id parameters.
	p, _ := esk.Argon2idParams.MarshalBinary()
	b.AddBytes(p)

	return b.Bytes()
}

// ErrInvalidEncryptedKeyPair is returned when an EncryptedKeyPair cannot be unmarshalled from the
// provided data.
var ErrInvalidEncryptedKeyPair = errors.New("invalid encrypted key pair")

func (esk *EncryptedSecretKey) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)

	if !(s.ReadUint8LengthPrefixed((*cryptobyte.String)(&esk.Salt)) &&
		s.ReadUint16LengthPrefixed((*cryptobyte.String)(&esk.Ciphertext)) &&
		s.ReadUint32(&esk.Time) &&
		s.ReadUint32(&esk.Memory) &&
		s.ReadUint8(&esk.Parallelism)) {
		return ErrInvalidEncryptedKeyPair
	}

	return nil
}

func (esk *EncryptedSecretKey) MarshalText() ([]byte, error) {
	b, err := esk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	t := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(t, b)

	return t, nil
}

func (esk *EncryptedSecretKey) UnmarshalText(text []byte) error {
	b, err := base64.RawURLEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return esk.UnmarshalBinary(b)
}

func (esk *EncryptedSecretKey) String() string {
	t, _ := esk.MarshalText()
	return string(t)
}

var (
	_ encoding.BinaryMarshaler   = &EncryptedSecretKey{}
	_ encoding.BinaryUnmarshaler = &EncryptedSecretKey{}
	_ encoding.TextMarshaler     = &EncryptedSecretKey{}
	_ encoding.TextUnmarshaler   = &EncryptedSecretKey{}
	_ fmt.Stringer               = &EncryptedSecretKey{}
)

// NewEncryptedSecretKey encrypts the given key pair with the given password.
func NewEncryptedSecretKey(sk *SecretKey, password []byte, params *Argon2idParams) (*EncryptedSecretKey, error) {
	// Use default parameters if none are provided.
	if params == nil {
		// As recommended in https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-7.4.
		params = &Argon2idParams{
			Time:        1,
			Memory:      1 * 1024 * 1024, // 1GiB
			Parallelism: 4,
		}
	}

	// Generate a random 16-byte salt.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Use Argon2id to derive a key and nonce from the password and salt.
	key, nonce := pbeKDF(password, salt, params)

	// Encrypt the secret key.
	aead, _ := chacha20poly1305.New(key)
	ciphertext := aead.Seal(nil, nonce, sk.s.Bytes(), nil)

	// Return the salt, ciphertext, and parameters.
	return &EncryptedSecretKey{
		Salt:           salt,
		Ciphertext:     ciphertext,
		Argon2idParams: *params,
	}, nil
}

// Decrypt uses the given password to decrypt the key pair. Returns an error if the password is
// incorrect or if the encrypted key pair has been modified.
func (esk *EncryptedSecretKey) Decrypt(password []byte) (*SecretKey, error) {
	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	// Use Argon2id to derive a key and nonce from the password and salt.
	key, nonce := pbeKDF(password, esk.Salt, &esk.Argon2idParams)
	aead, _ := chacha20poly1305.New(key)

	// Decrypt the secret key.
	plaintext, err := aead.Open(nil, nonce, esk.Ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	// Decode the secret key.
	if err := s.UnmarshalBinary(plaintext); err != nil {
		return nil, err
	}

	// Derive the public key.
	sk2pk(&q, &s)

	// Derive its Elligator2 representative.
	rk := pk2rk(&q)

	return &SecretKey{s: s, pk: PublicKey{q: q, rk: rk}}, err
}

// pbeKDF uses Argon2id to derive a ChaCha20 key and nonce from the password, salt, and parameters.
func pbeKDF(password, salt []byte, params *Argon2idParams) ([]byte, []byte) {
	kn := argon2.IDKey(password, salt, params.Time, params.Memory, params.Parallelism, chachaKDFLen)

	return kn[:chacha20poly1305.KeySize], kn[chacha20poly1305.KeySize:]
}

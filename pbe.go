package veil

import (
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

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

func (ekp *EncryptedSecretKey) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)

	// Encode the salt with an 8-bit length prefix.
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(ekp.Salt)
	})

	// Encode the ciphertext with a 16-bit length prefix.
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(ekp.Ciphertext)
	})

	// Encode the Argon2id parameters.
	p, _ := ekp.Argon2idParams.MarshalBinary()
	b.AddBytes(p)

	return b.Bytes()
}

// ErrInvalidEncryptedKeyPair is returned when an EncryptedKeyPair cannot be unmarshalled from the
// provided data.
var ErrInvalidEncryptedKeyPair = errors.New("invalid encrypted key pair")

func (ekp *EncryptedSecretKey) UnmarshalBinary(data []byte) error {
	var salt, ciphertext cryptobyte.String

	s := cryptobyte.String(data)

	if !(s.ReadUint8LengthPrefixed(&salt) &&
		s.ReadUint16LengthPrefixed(&ciphertext) &&
		s.ReadUint32(&ekp.Time) &&
		s.ReadUint32(&ekp.Memory) &&
		s.ReadUint8(&ekp.Parallelism)) {
		return ErrInvalidEncryptedKeyPair
	}

	ekp.Salt = salt
	ekp.Ciphertext = ciphertext

	return nil
}

func (ekp *EncryptedSecretKey) MarshalText() ([]byte, error) {
	b, err := ekp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	t := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(t, b)

	return t, nil
}

func (ekp *EncryptedSecretKey) UnmarshalText(text []byte) error {
	b, err := base64.RawURLEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return ekp.UnmarshalBinary(b)
}

func (ekp *EncryptedSecretKey) String() string {
	t, _ := ekp.MarshalText()
	return string(t)
}

var (
	_ encoding.BinaryMarshaler   = &EncryptedSecretKey{}
	_ encoding.BinaryUnmarshaler = &EncryptedSecretKey{}
	_ encoding.TextMarshaler     = &EncryptedSecretKey{}
	_ encoding.TextUnmarshaler   = &EncryptedSecretKey{}
	_ fmt.Stringer               = &EncryptedSecretKey{}
)

//nolint:gochecknoglobals // just a constant
// defaultParams is the set of default parameters, chosen for a balance of security and speed.
var defaultParams = &Argon2idParams{
	Time:        4,
	Memory:      1 * 1024 * 1024, // 1GiB
	Parallelism: 4,
}

const (
	pbeSaltLen = 16 // The length of PBE salts, in bytes.
)

// NewEncryptedSecretKey encrypts the given key pair with the given password.
func NewEncryptedSecretKey(
	rand io.Reader, sk *SecretKey, password []byte, params *Argon2idParams,
) (*EncryptedSecretKey, error) {
	// Use default parameters if none are provided.
	if params == nil {
		params = defaultParams
	}

	// Generate a random salt.
	salt := make([]byte, pbeSaltLen)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, err
	}

	// Encode the Argon2id parameters as authenticated data.
	data, _ := params.MarshalBinary()

	// Use Argon2id to derive a key and nonce from the password and salt.
	key, nonce := pbeKDF(password, salt, params)

	// Encrypt the secret key.
	aead, _ := chacha20poly1305.New(key)
	ciphertext := aead.Seal(nil, nonce, sk.s.Bytes(), data)

	// Return the salt, ciphertext, and parameters.
	return &EncryptedSecretKey{
		Salt:           salt,
		Ciphertext:     ciphertext,
		Argon2idParams: *params,
	}, nil
}

// Decrypt uses the given password to decrypt the key pair. Returns an error if the password is
// incorrect or if the encrypted key pair has been modified.
func (ekp *EncryptedSecretKey) Decrypt(password []byte) (*SecretKey, error) {
	// Encode the Argon parameters as authenticated data.
	data, _ := ekp.Argon2idParams.MarshalBinary()

	// Use Argon2id to derive a key and nonce from the password and salt.
	key, nonce := pbeKDF(password, ekp.Salt, &ekp.Argon2idParams)
	aead, _ := chacha20poly1305.New(key)

	// Decrypt the secret key.
	plaintext, err := aead.Open(nil, nonce, ekp.Ciphertext, data)
	if err != nil {
		return nil, err
	}

	// Decode the secret key.
	var s ristretto.Scalar
	if err := s.UnmarshalBinary(plaintext); err != nil {
		return nil, err
	}

	// Derive the public key.
	q := sk2pk(&s)

	// Derive its Elligator2 representative.
	rk, err := pk2rk(&q)
	if err != nil {
		return nil, err
	}

	return &SecretKey{s: s, pk: PublicKey{q: q, rk: rk}}, err
}

// pbeKDF uses Argon2id to derive a ChaCha20 key and nonce from the password, salt, and parameters.
func pbeKDF(password, salt []byte, params *Argon2idParams) ([]byte, []byte) {
	k := argon2.IDKey(password, salt, params.Time, params.Memory, params.Parallelism,
		chacha20poly1305.KeySize+chacha20poly1305.NonceSize)
	key := k[:chacha20poly1305.KeySize]
	nonce := k[chacha20poly1305.KeySize:]

	return key, nonce
}

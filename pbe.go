package veil

import (
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"

	"github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
)

// EncryptedSecretKey is a SecretKey that has been encrypted with a password.
type EncryptedSecretKey struct {
	Salt         []byte
	Ciphertext   []byte
	Time, Memory uint32
	Threads      uint8
}

func (ekp *EncryptedSecretKey) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint24LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(ekp.Salt)
	})
	b.AddUint24LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(ekp.Ciphertext)
	})
	b.AddUint32(ekp.Time)
	b.AddUint32(ekp.Memory)
	b.AddUint8(ekp.Threads)

	return b.Bytes()
}

var ErrInvalidEncryptedKeyPair = errors.New("invalid encrypted key pair")

func (ekp *EncryptedSecretKey) UnmarshalBinary(data []byte) error {
	var salt, ciphertext cryptobyte.String

	s := cryptobyte.String(data)

	if !(s.ReadUint24LengthPrefixed(&salt) &&
		s.ReadUint24LengthPrefixed(&ciphertext) &&
		s.ReadUint32(&ekp.Time) &&
		s.ReadUint32(&ekp.Memory) &&
		s.ReadUint8(&ekp.Threads)) {
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

const (
	defaultTime   = 1
	defaultMemory = 64 * 1024
)

// NewEncryptedSecretKey encrypts the given key pair with the given password.
func NewEncryptedSecretKey(rand io.Reader, sk *SecretKey, password []byte) (*EncryptedSecretKey, error) {
	salt := make([]byte, 32)

	// Generate a random salt.
	_, err := io.ReadFull(rand, salt)
	if err != nil {
		return nil, err
	}

	// Use all available CPUs.
	threads := uint8(math.MaxUint8)
	if n := runtime.NumCPU(); n <= math.MaxUint8 {
		threads = uint8(n)
	}

	// Use Argon2id to derive a key and nonce from the password and salt.
	k := argon2.IDKey(password, salt, defaultTime, defaultMemory, threads, kdfOutputLen)

	// Encode the Argon2id parameters as authenticated data.
	data := encodeArgonParams(defaultTime, defaultMemory, threads)

	// Encrypt the secret key.
	aead, _ := chacha20poly1305.New(k[:chacha20poly1305.KeySize])
	ciphertext := aead.Seal(nil, k[chacha20poly1305.KeySize:], sk.s.Bytes(), data)

	// Return the salt, ciphertext, and parameters.
	return &EncryptedSecretKey{
		Salt:       salt,
		Ciphertext: ciphertext,
		Time:       defaultTime,
		Memory:     defaultMemory,
		Threads:    threads,
	}, nil
}

// Decrypt uses the given password to decrypt the key pair. Returns an error if the password is
// incorrect or if the encrypted key pair has been modified.
func (ekp *EncryptedSecretKey) Decrypt(password []byte) (*SecretKey, error) {
	// Use Argon2id to derive a key and nonce from the password and salt.
	k := argon2.IDKey(password, ekp.Salt, ekp.Time, ekp.Memory, ekp.Threads, kdfOutputLen)

	// Encode the Argon parameters as authenticated data.
	data := encodeArgonParams(ekp.Time, ekp.Memory, ekp.Threads)

	aead, _ := chacha20poly1305.New(k[:chacha20poly1305.KeySize])

	// Decrypt the secret key.
	b, err := aead.Open(nil, k[chacha20poly1305.KeySize:], ekp.Ciphertext, data)
	if err != nil {
		return nil, err
	}

	// Decode the secret key.
	var s ristretto.Scalar
	if err := s.UnmarshalBinary(b); err != nil {
		return nil, err
	}

	// Derive the public key.
	q := sk2pk(&s)

	return &SecretKey{s: s, q: *q}, err
}

// encodeArgonParams returns the Argon2id params encoded as big-endian integers.
func encodeArgonParams(time, memory uint32, threads uint8) []byte {
	data := make([]byte, 9)
	binary.BigEndian.PutUint32(data, time)
	binary.BigEndian.PutUint32(data[4:], memory)
	data[8] = threads

	return data
}

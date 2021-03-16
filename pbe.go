package veil

import (
	"encoding"
	"encoding/base64"
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

	// Encode the Argon2id parameters as authenticated data.
	data := encodeArgonParams(defaultTime, defaultMemory, threads)

	// Use Argon2id to derive a key and nonce from the password and salt.
	key, nonce := pbeKDF(password, salt, defaultTime, defaultMemory, threads)

	// Encrypt the secret key.
	aead, _ := chacha20poly1305.New(key)
	ciphertext := aead.Seal(nil, nonce, sk.s.Bytes(), data)

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
	// Encode the Argon parameters as authenticated data.
	data := encodeArgonParams(ekp.Time, ekp.Memory, ekp.Threads)

	// Use Argon2id to derive a key and nonce from the password and salt.
	key, nonce := pbeKDF(password, ekp.Salt, ekp.Time, ekp.Memory, ekp.Threads)
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

// encodeArgonParams returns the Argon2id params encoded as big-endian integers.
func encodeArgonParams(time, memory uint32, threads uint8) []byte {
	b := cryptobyte.NewFixedBuilder(make([]byte, 0, 9))
	b.AddUint32(time)
	b.AddUint32(memory)
	b.AddUint8(threads)

	return b.BytesOrPanic()
}

// pbeKDF uses Argon2id to derive a ChaCha20 key and nonce from the password, salt, and parameters.
func pbeKDF(password, salt []byte, time, memory uint32, threads uint8) ([]byte, []byte) {
	k := argon2.IDKey(password, salt, time, memory, threads, chacha20poly1305.KeySize+chacha20poly1305.NonceSize)
	key := k[:chacha20poly1305.KeySize]
	nonce := k[chacha20poly1305.KeySize:]

	return key, nonce
}

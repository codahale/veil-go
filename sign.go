package veil

import (
	"crypto/sha512"
	"encoding"
	"errors"
	"fmt"
	"io"

	"github.com/codahale/veil/internal/xdh"
)

// Signature is a ristretto255/Schnorr signature.
//
// Technically, it's the Elligator2 encoding of a ristretto255 point prepended to a ristretto255
// scalar and is indistinguishable from random noise. It can be marshalled and unmarshalled as a
// base32 string for human consumption.
type Signature []byte

// MarshalText encodes the signature into unpadded base32 text and returns the result.
func (s Signature) MarshalText() (text []byte, err error) {
	text = make([]byte, pkEncoding.EncodedLen(len(s)))

	pkEncoding.Encode(text, s)

	return
}

// UnmarshalText decodes the results of MarshalText and updates the receiver to contain the decoded
// signature.
func (s *Signature) UnmarshalText(text []byte) error {
	data := make([]byte, xdh.SignatureSize)

	_, err := pkEncoding.Decode(data, text)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	*s = data

	return nil
}

// String returns the signature as unpadded base32 text.
func (s Signature) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

var (
	_ encoding.TextMarshaler   = Signature{}
	_ encoding.TextUnmarshaler = &Signature{}
	_ fmt.Stringer             = Signature{}
)

// Sign returns a detached signature of the contents of src.
func (sk SecretKey) Sign(src io.Reader) (Signature, error) {
	h := sha512.New()

	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}

	return xdh.Sign(sk, h.Sum(nil))
}

// ErrInvalidSignature is returned when a signature, public key, and message do not match.
var ErrInvalidSignature = errors.New("invalid signature")

// Verify returns nil if the given signature was created by the owner of the given public key for
// the contents of src, otherwise ErrInvalidSignature.
func (pk PublicKey) Verify(src io.Reader, sig Signature) error {
	h := sha512.New()

	if _, err := io.Copy(h, src); err != nil {
		return err
	}

	if !xdh.Verify(pk, h.Sum(nil), sig) {
		return ErrInvalidSignature
	}

	return nil
}

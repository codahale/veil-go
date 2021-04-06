package veil

import (
	"encoding"
	"fmt"

	"github.com/codahale/veil/pkg/veil/internal/schnorr"
)

// Signature is a digital signature of a message, created by the holder of a secret key, which can
// be verified by anyone with the corresponding public key.
type Signature struct {
	b []byte
}

// MarshalBinary encodes the signature into bytes.
func (s *Signature) MarshalBinary() (data []byte, err error) {
	return s.b, nil
}

// UnmarshalBinary decodes the signature from bytes.
func (s *Signature) UnmarshalBinary(data []byte) error {
	if len(data) != schnorr.SignatureSize {
		return ErrInvalidSignature
	}

	s.b = data

	return nil
}

// MarshalText encodes the signature into unpadded base32 text and returns the result.
func (s *Signature) MarshalText() (text []byte, err error) {
	data, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}

	text = make([]byte, asciiEncoding.EncodedLen(len(data)))

	asciiEncoding.Encode(text, data)

	return
}

// UnmarshalText decodes the results of MarshalText and updates the receiver to contain the decoded
// signature.
func (s *Signature) UnmarshalText(text []byte) error {
	data := make([]byte, asciiEncoding.DecodedLen(len(text)))

	_, err := asciiEncoding.Decode(data, text)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return s.UnmarshalBinary(data)
}

// String returns the signature as unpadded base32 text.
func (s *Signature) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

var (
	_ encoding.BinaryMarshaler   = &Signature{}
	_ encoding.BinaryUnmarshaler = &Signature{}
	_ encoding.TextMarshaler     = &Signature{}
	_ encoding.TextUnmarshaler   = &Signature{}
	_ fmt.Stringer               = &Signature{}
)

package veil

import (
	"crypto/sha512"
	"encoding"
	"errors"
	"fmt"
	"io"

	"github.com/codahale/veil/internal/stream"
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

// ErrInvalidSignature is returned when a signature, public key, and message do not match.
var ErrInvalidSignature = errors.New("invalid signature")

// SignDetached returns a detached signature of the contents of src.
func (sk SecretKey) SignDetached(src io.Reader) (Signature, error) {
	h := sha512.New()

	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}

	return xdh.Sign(sk, h.Sum(nil))
}

// Sign copies src to dst, creates a signature of the contents of src, and appends it to src.
func (sk SecretKey) Sign(dst io.Writer, src io.Reader) (int64, error) {
	// Tee all reads from src into an SHA-512 hash.
	h := sha512.New()
	r := io.TeeReader(src, h)

	// Copy all data from src into dst via h.
	n, err := io.Copy(dst, r)
	if err != nil {
		return n, err
	}

	// Sign the SHA-512 hash of the message.
	sig, err := xdh.Sign(sk, h.Sum(nil))
	if err != nil {
		return n, err
	}

	// Append the signature.
	sn, err := dst.Write(sig)

	// Return the bytes written and any errors.
	return n + int64(sn), err
}

// VerifyDetached returns nil if the given signature was created by the owner of the given public
// key for the contents of src, otherwise ErrInvalidSignature.
func (pk PublicKey) VerifyDetached(src io.Reader, sig Signature) error {
	h := sha512.New()

	if _, err := io.Copy(h, src); err != nil {
		return err
	}

	if !xdh.Verify(pk, h.Sum(nil), sig) {
		return ErrInvalidSignature
	}

	return nil
}

// Verify copies src to dst, removing the appended signature and verifying it.
func (pk PublicKey) Verify(dst io.Writer, src io.Reader) (int64, error) {
	sr := stream.NewSignatureReader(src)

	// Copy all data from src into dst, skipping the appended signature.
	n, err := io.Copy(dst, sr)
	if err != nil {
		return n, err
	}

	// Verify the signature.
	if !xdh.Verify(pk, sr.SHA512.Sum(nil), sr.Signature) {
		return n, ErrInvalidSignature
	}

	return n, nil
}

package veil

import (
	"encoding"
	"errors"
	"fmt"
	"io"

	"github.com/codahale/veil/internal/r255"
	"github.com/codahale/veil/internal/scopedhash"
	"github.com/codahale/veil/internal/stream"
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
	if len(data) != r255.SignatureSize {
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

// ErrInvalidSignature is returned when a signature, public key, and message do not match.
var ErrInvalidSignature = errors.New("invalid signature")

// SignDetached returns a detached signature of the contents of src using the given derivation path.
// The signature can be verified with the public key derived from the same secret key using the same
// derivation path.
func (sk *SecretKey) SignDetached(src io.Reader, derivationPath string) (*Signature, error) {
	// Hash the message.
	h := scopedhash.NewMessageHash()
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}

	// Create a signature of the hash.
	return &Signature{b: sk.privateKey(derivationPath).Sign(h.Sum(nil))}, nil
}

// Sign copies src to dst, creates a signature of the contents of src using the given derivation
// path, and appends it to src. The signature can be verified with the public key derived from the
// same secret key using the same derivation path.
func (sk *SecretKey) Sign(dst io.Writer, src io.Reader, derivationPath string) (int64, error) {
	// Tee all reads from src into an SHA-512 hash.
	h := scopedhash.NewMessageHash()
	r := io.TeeReader(src, h)

	// Copy all data from src into dst via h.
	n, err := io.Copy(dst, r)
	if err != nil {
		return n, err
	}

	// Sign the SHA-512 hash of the message.
	sig := sk.privateKey(derivationPath).Sign(h.Sum(nil))

	// Append the signature.
	sn, err := dst.Write(sig)

	// Return the bytes written and any errors.
	return n + int64(sn), err
}

// VerifyDetached returns nil if the given signature was created by the owner of the given public
// key for the contents of src, otherwise ErrInvalidSignature.
func (pk *PublicKey) VerifyDetached(src io.Reader, sig *Signature) error {
	// Hash the message.
	h := scopedhash.NewMessageHash()
	if _, err := io.Copy(h, src); err != nil {
		return err
	}

	// Verify the signature against the hash of the message.
	if !pk.k.Verify(h.Sum(nil), sig.b) {
		return ErrInvalidSignature
	}

	return nil
}

// Verify copies src to dst, removing the appended signature and verifying it.
func (pk *PublicKey) Verify(dst io.Writer, src io.Reader) (int64, error) {
	// Hash the message and detach the signature.
	h := scopedhash.NewMessageHash()
	sr := stream.NewSignatureReader(src, h, r255.SignatureSize)

	// Copy all data from src into dst, skipping the appended signature.
	n, err := io.Copy(dst, sr)
	if err != nil {
		return n, err
	}

	// Verify the signature.
	if !pk.k.Verify(h.Sum(nil), sr.Signature) {
		return n, ErrInvalidSignature
	}

	return n, nil
}

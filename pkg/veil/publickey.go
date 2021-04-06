package veil

import (
	"encoding"
	"fmt"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/codahale/veil/pkg/veil/internal/protocols/scaldf"
	"github.com/codahale/veil/pkg/veil/internal/protocols/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/protocols/schnorr/sigio"
	"github.com/gtank/ristretto255"
)

// PublicKey is a key that's used to verify and encrypt messages.
//
// It can be marshalled and unmarshalled as a base32 string for human consumption.
type PublicKey struct {
	q *ristretto255.Element
}

// Derive derives a PublicKey from the receiver with the given sub-key ID.
func (pk *PublicKey) Derive(subKeyID string) *PublicKey {
	q := pk.q

	for _, id := range splitID(subKeyID) {
		q = scaldf.DeriveElement(q, id)
	}

	return &PublicKey{q: q}
}

// VerifyDetached returns nil if the given signature was created by the owner of the given public
// key for the contents of src, otherwise ErrInvalidSignature.
func (pk *PublicKey) VerifyDetached(src io.Reader, sig *Signature) error {
	// Read the message contents through the schnorr STROBE protocol.
	verifier := schnorr.NewVerifier(src)
	if _, err := io.Copy(io.Discard, verifier); err != nil {
		return err
	}

	// Verify the signature against the message.
	if !verifier.Verify(pk.q, sig.b) {
		return ErrInvalidSignature
	}

	return nil
}

// Verify copies src to dst, removing the appended signature and verifying it.
func (pk *PublicKey) Verify(dst io.Writer, src io.Reader) (int64, error) {
	// Copy the message contents to dst through the verifier STROBE protocol and detatch the
	// signature.
	sr := sigio.NewReader(src, schnorr.SignatureSize)
	verifier := schnorr.NewVerifier(sr)

	// Copy all data from src into dst via verifier, skipping the appended signature.
	n, err := io.Copy(dst, verifier)
	if err != nil {
		return n, err
	}

	// Verify the signature against the message.
	sig := sr.Signature
	if !verifier.Verify(pk.q, sig) {
		return n, ErrInvalidSignature
	}

	return n, nil
}

// String returns the public key as unpadded base32 text.
func (pk *PublicKey) String() string {
	text, err := pk.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalBinary encodes the public key into a 32-byte slice.
func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.q.Encode(nil), nil
}

// UnmarshalBinary decodes the public key from a 32-byte slice.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	q := ristretto255.NewElement()
	if err := q.Decode(data); err != nil {
		return err
	}

	pk.q = q

	return nil
}

// MarshalText encodes the public key into unpadded base32 text and returns the result.
func (pk *PublicKey) MarshalText() (text []byte, err error) {
	b := pk.q.Encode(nil)

	text = make([]byte, asciiEncoding.EncodedLen(len(b)))

	asciiEncoding.Encode(text, b)

	return
}

// UnmarshalText decodes the results of MarshalText and updates the receiver to contain the decoded
// public key.
func (pk *PublicKey) UnmarshalText(text []byte) error {
	data := make([]byte, protocols.ElementSize)

	// Decode from base32.
	_, err := asciiEncoding.Decode(data, text)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Decode as a ristretto255 element.
	return pk.UnmarshalBinary(data)
}

var (
	_ encoding.BinaryMarshaler   = &PublicKey{}
	_ encoding.BinaryUnmarshaler = &PublicKey{}
	_ encoding.TextMarshaler     = &PublicKey{}
	_ encoding.TextUnmarshaler   = &PublicKey{}
	_ fmt.Stringer               = &PublicKey{}
)

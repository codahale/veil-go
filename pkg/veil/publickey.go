package veil

import (
	"encoding"
	"fmt"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/scaldf"
	"github.com/codahale/veil/pkg/veil/internal/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/schnorr/sigio"
	"github.com/gtank/ristretto255"
)

// PublicKey is a key that's used to verify and encrypt messages.
//
// It can be marshalled and unmarshalled as a base58 string for human consumption.
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
	// Write the message contents to the schnorr STROBE protocol.
	verifier := schnorr.NewVerifier(pk.q, nil)
	if _, err := io.Copy(verifier, src); err != nil {
		return err
	}

	// Verify the signature against the message.
	if !verifier.Verify(sig.b) {
		return ErrInvalidSignature
	}

	return nil
}

// Verify copies src to dst, removing the appended signature and verifying it.
func (pk *PublicKey) Verify(dst io.Writer, src io.Reader) (int64, error) {
	// Detach the signature from src.
	sr := sigio.NewReader(src)
	verifier := schnorr.NewVerifier(pk.q, nil)

	// Copy all data from src into dst and verifier, skipping the appended signature.
	n, err := io.Copy(io.MultiWriter(dst, verifier), sr)
	if err != nil {
		return n, err
	}

	// Verify the signature against the message.
	sig := sr.Signature
	if !verifier.Verify(sig) {
		return n, ErrInvalidSignature
	}

	return n, nil
}

// String returns the public key as base58 text.
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
		return fmt.Errorf("invalid public key: %w", err)
	}

	pk.q = q

	return nil
}

// MarshalText encodes the public key into base58 text and returns the result.
func (pk *PublicKey) MarshalText() (text []byte, err error) {
	return internal.ASCIIEncode(pk.q.Encode(nil)), nil
}

// UnmarshalText decodes the results of MarshalText and updates the receiver to contain the decoded
// public key.
func (pk *PublicKey) UnmarshalText(text []byte) error {
	data, err := internal.ASCIIDecode(text)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	return pk.UnmarshalBinary(data)
}

var (
	_ encoding.BinaryMarshaler   = &PublicKey{}
	_ encoding.BinaryUnmarshaler = &PublicKey{}
	_ encoding.TextMarshaler     = &PublicKey{}
	_ encoding.TextUnmarshaler   = &PublicKey{}
	_ fmt.Stringer               = &PublicKey{}
)

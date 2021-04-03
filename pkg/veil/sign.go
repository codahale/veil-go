package veil

import (
	"errors"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/codahale/veil/pkg/veil/internal/scopedhash"
	"github.com/codahale/veil/pkg/veil/internal/stream"
)

// ErrInvalidSignature is returned when a signature, public key, and message do not match.
var ErrInvalidSignature = errors.New("invalid signature")

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

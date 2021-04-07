package veil

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/scaldf"
	"github.com/codahale/veil/pkg/veil/internal/schnorr"
	"github.com/gtank/ristretto255"
)

// PrivateKey is a private key derived from a SecretKey, used to decrypt and sign messages.
type PrivateKey struct {
	d *ristretto255.Scalar
	q *ristretto255.Element
}

// PublicKey returns the corresponding PublicKey for the receiver.
func (pk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{q: pk.q}
}

// Derive derives a PrivateKey from the receiver with the given sub-key ID.
func (pk *PrivateKey) Derive(subKeyID string) *PrivateKey {
	d := pk.d

	// Derive the chain of private key scalars.
	for _, id := range splitID(subKeyID) {
		d = scaldf.DeriveScalar(d, id)
	}

	// Calculate the public key element.
	q := ristretto255.NewElement().ScalarBaseMult(d)

	return &PrivateKey{d: d, q: q}
}

// SignDetached returns a detached signature of the contents of src.
func (pk *PrivateKey) SignDetached(src io.Reader) (*Signature, error) {
	// Write the message contents to the schnorr STROBE protocol.
	signer := schnorr.NewSigner(nil)
	if _, err := io.Copy(signer, src); err != nil {
		return nil, err
	}

	// Create a signature of the message.
	sig := signer.Sign(pk.d, pk.q)

	return &Signature{b: sig}, nil
}

// Sign copies src to dst, creates a signature of the contents of src, and appends it to dst.
func (pk *PrivateKey) Sign(dst io.Writer, src io.Reader) (int64, error) {
	// Write the message contents to the schnorr STROBE protocol.
	signer := schnorr.NewSigner(nil)

	// Copy all data from src into dst and signer.
	n, err := io.Copy(io.MultiWriter(dst, signer), src)
	if err != nil {
		return n, err
	}

	// Create a signature of the message.
	sig := signer.Sign(pk.d, pk.q)

	// Append the signature.
	sn, err := dst.Write(sig)

	// Return the bytes written and any errors.
	return n + int64(sn), err
}

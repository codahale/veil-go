package veil

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols/msghash"
	"github.com/codahale/veil/pkg/veil/internal/protocols/scaldf"
	"github.com/codahale/veil/pkg/veil/internal/protocols/schnorr"
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
	// Write the message contents to the msghash STROBE protocol.
	h := msghash.NewWriter(msghash.DigestSize)
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}

	// Create a signature of the digest.
	sig := schnorr.Sign(pk.d, pk.q, h.Digest())

	return &Signature{b: sig}, nil
}

// Sign copies src to dst, creates a signature of the contents of src, and appends it to dst.
func (pk *PrivateKey) Sign(dst io.Writer, src io.Reader) (int64, error) {
	// Tee all reads from src into the msghash STROBE protocol.
	h := msghash.NewWriter(msghash.DigestSize)
	r := io.TeeReader(src, h)

	// Copy all data from src into dst via msghash.
	n, err := io.Copy(dst, r)
	if err != nil {
		return n, err
	}

	// Create a signature of the digest.
	sig := schnorr.Sign(pk.d, pk.q, h.Digest())

	// Append the signature.
	sn, err := dst.Write(sig)

	// Return the bytes written and any errors.
	return n + int64(sn), err
}

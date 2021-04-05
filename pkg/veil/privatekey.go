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
}

// PublicKey returns the corresponding PublicKey for the receiver.
func (pk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{q: ristretto255.NewElement().ScalarBaseMult(pk.d)}
}

// Derive derives a PrivateKey from the receiver with the given sub-key ID.
func (pk *PrivateKey) Derive(subKeyID string) *PrivateKey {
	d := pk.d

	for _, id := range splitID(subKeyID) {
		d = scaldf.DeriveScalar(d, id)
	}

	return &PrivateKey{d: d}
}

// SignDetached returns a detached signature of the contents of src.
func (pk *PrivateKey) SignDetached(src io.Reader) (*Signature, error) {
	// Write the message contents to the msghash STROBE protocol.
	h := msghash.NewWriter(digestSize)
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}

	// Create a signature of the digest.
	sigA, sigB := schnorr.Sign(pk.d, pk.PublicKey().q, h.Digest())

	return &Signature{b: append(sigA, sigB...)}, nil
}

// Sign copies src to dst, creates a signature of the contents of src, and appends it to dst.
func (pk *PrivateKey) Sign(dst io.Writer, src io.Reader) (int64, error) {
	// Tee all reads from src into the msghash STROBE protocol.
	h := msghash.NewWriter(digestSize)
	r := io.TeeReader(src, h)

	// Copy all data from src into dst via msghash.
	n, err := io.Copy(dst, r)
	if err != nil {
		return n, err
	}

	// Create a signature of the digest.
	sigA, sigB := schnorr.Sign(pk.d, pk.PublicKey().q, h.Digest())

	// Append the signature.
	sn, err := dst.Write(append(sigA, sigB...))

	// Return the bytes written and any errors.
	return n + int64(sn), err
}

const digestSize = 64

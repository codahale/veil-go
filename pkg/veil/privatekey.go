package veil

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/dxof"
	"github.com/codahale/veil/pkg/veil/internal/r255"
)

// PrivateKey is a private key derived from a SecretKey, used to decrypt and sign messages.
type PrivateKey struct {
	k *r255.PrivateKey
}

// PublicKey returns the corresponding PublicKey for the receiver.
func (pk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{k: pk.k.PublicKey()}
}

// Derive derives a PrivateKey from the receiver with the given sub-key ID.
func (pk *PrivateKey) Derive(subKeyID string) *PrivateKey {
	key := pk.k

	for _, id := range splitID(subKeyID) {
		key = key.Derive(id)
	}

	return &PrivateKey{k: key}
}

// SignDetached returns a detached signature of the contents of src.
func (pk *PrivateKey) SignDetached(src io.Reader) (*Signature, error) {
	// Write the message contents to an XOF.
	xof := dxof.MessageDigest()
	if _, err := io.Copy(xof, src); err != nil {
		return nil, err
	}

	// Calculate a digest of the message.
	digest := make([]byte, digestSize)
	_, _ = io.ReadFull(xof, digest)

	// Create a signature of the digest.
	return &Signature{b: pk.k.Sign(digest)}, nil
}

// Sign copies src to dst, creates a signature of the contents of src, and appends it to dst.
func (pk *PrivateKey) Sign(dst io.Writer, src io.Reader) (int64, error) {
	// Tee all reads from src into an XOF.
	xof := dxof.MessageDigest()
	r := io.TeeReader(src, xof)

	// Copy all data from src into dst via xof.
	n, err := io.Copy(dst, r)
	if err != nil {
		return n, err
	}

	// Calculate a digest of the message.
	digest := make([]byte, digestSize)
	_, _ = io.ReadFull(xof, digest)

	// Sign the digest.
	sig := pk.k.Sign(digest)

	// Append the signature.
	sn, err := dst.Write(sig)

	// Return the bytes written and any errors.
	return n + int64(sn), err
}

const digestSize = 64

package veil

import (
	"io"

	"github.com/codahale/veil/internal/r255"
	"github.com/codahale/veil/internal/scopedhash"
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
	// Hash the message.
	h := scopedhash.NewMessageHash()
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}

	// Create a signature of the hash.
	return &Signature{b: pk.k.Sign(h.Sum(nil))}, nil
}

// Sign copies src to dst, creates a signature of the contents of src, and appends it to dst.
func (pk *PrivateKey) Sign(dst io.Writer, src io.Reader) (int64, error) {
	// Tee all reads from src into an SHA-512 hash.
	h := scopedhash.NewMessageHash()
	r := io.TeeReader(src, h)

	// Copy all data from src into dst via h.
	n, err := io.Copy(dst, r)
	if err != nil {
		return n, err
	}

	// Sign the SHA-512 hash of the message.
	sig := pk.k.Sign(h.Sum(nil))

	// Append the signature.
	sn, err := dst.Write(sig)

	// Return the bytes written and any errors.
	return n + int64(sn), err
}

package veil

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/hpke"
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

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes copied and the first
// error reported while encrypting, if any.
func (pk *PrivateKey) Encrypt(dst io.Writer, src io.Reader, recipients []*PublicKey, padding int) (int64, error) {
	qRs := make([]*ristretto255.Element, len(recipients))

	for i, pk := range recipients {
		qRs[i] = pk.q
	}

	return hpke.Encrypt(dst, src, pk.d, pk.q, qRs, padding)
}

// Decrypt decrypts the data in src if originally encrypted by the given public key. Returns the
// number of decrypted bytes written, and the first reported error, if any.
//
// N.B.: Because Veil messages are streamed, it is possible that this may write some decrypted data
// to dst before it can discover that the ciphertext is invalid. If Decrypt returns an error, all
// output written to dst should be discarded, as it cannot be ascertained to be authentic.
func (pk *PrivateKey) Decrypt(dst io.Writer, src io.ReadSeeker, sender *PublicKey) (int64, error) {
	return hpke.Decrypt(dst, src, pk.d, pk.q, sender.q)
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

// Sign returns a signature of the contents of src.
func (pk *PrivateKey) Sign(src io.Reader) (*Signature, error) {
	// Write the message contents to the veil.schnorr STROBE protocol.
	signer := schnorr.NewSigner(pk.d, pk.q, nil)
	if _, err := io.Copy(signer, src); err != nil {
		return nil, err
	}

	// Create a signature of the message.
	sig := signer.Sign()

	return &Signature{b: sig}, nil
}

package veil

import (
	"bufio"
	"crypto/rand"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/mres"
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
func (pk *PrivateKey) Encrypt(
	dst io.Writer, src io.Reader, recipients []*PublicKey, fakes, padding int,
) (int64, error) {
	buf := make([]byte, internal.UniformBytestringSize)
	qRs := make([]*ristretto255.Element, len(recipients)+fakes)

	// Copy recipients.
	for i, pk := range recipients {
		qRs[i] = pk.q
	}

	// Add fakes.
	for i := len(recipients); i < len(qRs); i++ {
		if _, err := rand.Read(buf); err != nil {
			return 0, err
		}

		qRs[i] = ristretto255.NewElement().FromUniformBytes(buf)
	}

	// Shuffle the recipients to disguise any ordering information.
	if err := shuffle(qRs); err != nil {
		return 0, err
	}

	in := bufio.NewReader(src)
	out := bufio.NewWriter(dst)

	n, err := mres.Encrypt(out, in, pk.d, pk.q, qRs, padding)
	if err != nil {
		return n, err
	}

	return n, out.Flush()
}

// Decrypt decrypts the data in src if originally encrypted by the given public key. Returns the
// number of decrypted bytes written, and the first reported error, if any.
//
// N.B.: Because Veil messages are streamed, it is possible that this may write some decrypted data
// to dst before it can discover that the ciphertext is invalid. If Decrypt returns an error, all
// output written to dst should be discarded, as it cannot be ascertained to be authentic.
func (pk *PrivateKey) Decrypt(dst io.Writer, src io.Reader, sender *PublicKey) (int64, error) {
	in := bufio.NewReader(src)
	out := bufio.NewWriter(dst)

	n, err := mres.Decrypt(out, in, pk.d, pk.q, sender.q)
	if err != nil {
		return n, err
	}

	return n, out.Flush()
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
	signer := schnorr.NewSigner(io.Discard)
	if _, err := io.Copy(signer, bufio.NewReader(src)); err != nil {
		return nil, err
	}

	// Create a signature of the message.
	sig, err := signer.Sign(pk.d, pk.q)
	if err != nil {
		return nil, err
	}

	return &Signature{b: sig}, nil
}

// shuffle performs an in-place Fisher-Yates shuffle, using crypto/rand to pick indexes.
func shuffle(keys []*ristretto255.Element) error {
	for i := len(keys) - 1; i > 0; i-- {
		// Randomly pick a card from the unshuffled deck.
		j, err := internal.IntN(i + 1)
		if err != nil {
			return err
		}

		// Swap it with the current card.
		keys[i], keys[j] = keys[j], keys[i]
	}

	return nil
}

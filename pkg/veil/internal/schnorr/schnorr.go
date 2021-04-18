// Package schnorr provides the underlying STROBE protocol for Veil's Schnorr signatures.
//
// Per Fleischhacker et al:
//
//     The (generalized) Schnorr signature scheme is indistinguishable with full key exposure,
//     in the random oracle model.
//
// Signing is as follows, given a message in blocks M_0...M_n, a private scalar d, and a public
// element Q:
//
//     INIT('veil.schnorr', level=256)
//     AD(Q)
//     SEND_CLR('',  more=false)
//     SEND_CLR(M_0, more=true)
//     SEND_CLR(M_1, more=true)
//     ...
//     SEND_CLR(M_n, more=true)
//
// This protocol's context is cloned and the clone is used to derive a deterministic nonce r from
// the previously-sent message contents and the signer's private scalar d:
//
//     KEY(d)
//     PRF(64) -> r
//
// Once r is generated, the clone's context is discarded and r is returned to the parent context:
//
//     R = rG
//     AD(R)
//	   PRF(64) -> c
//     s = d_sc + r
//
// The resulting signature consists of the two scalars, c and s.
//
// To verify, veil.schnorr is run with associated data D, message in blocks M_0...M_n, a public
// element Q:
//
//     INIT('veil.schnorr', level=256)
//     AD(Q)
//     RECV_CLR('',  more=false)
//     RECV_CLR(M_0, more=true)
//     RECV_CLR(M_1, more=true)
//     ...
//     RECV_CLR(M_n, more=true)
//     R' = -cQ + sG
//     AD(R')
//     PRF(64) -> c'
//
// Finally, the verifier compares c' == c. If the two scalars are equivalent, the signature is
// valid.
//
// This construction integrates message hashing with signature creation/validation, uses the
// sender's private key and the message to derive a challenge nonce, binds the signer's identity,
// and produces a signature which is indistinguishable from random noise without the signer's public
// key and the message.
//
// See https://eprint.iacr.org/2011/673.pdf
package schnorr

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocol"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
)

const (
	// SignatureSize is the length of a signature in bytes.
	SignatureSize = internal.ElementSize + internal.ScalarSize
)

// Signer is an io.Writer which adds written data to a STROBE protocol for signing.
type Signer struct {
	schnorr *protocol.Protocol
	d       *ristretto255.Scalar
}

// NewSigner returns a Signer instance with the signer's key pair.
func NewSigner(d *ristretto255.Scalar, q *ristretto255.Element) *Signer {
	// Initialize a new protocol.
	schnorr := protocol.New("veil.schnorr")

	// Add the signer's public key to the protocol.
	schnorr.AD(q.Encode(nil))

	// Prep it for streaming cleartext.
	schnorr.SendCLR(nil)

	return &Signer{schnorr: schnorr, d: d}
}

func (sn *Signer) Write(p []byte) (n int, err error) {
	// Update the protocol with the written data.
	sn.schnorr.MoreSendCLR(p)

	return len(p), nil
}

// Sign uses the given key pair to construct a deterministic Schnorr signature of the previously
// written data.
func (sn *Signer) Sign() []byte {
	var buf [SignatureSize]byte

	// Clone the protocol context. This step requires knowledge of the signer's private key, so it
	// can't be part of the verification process.
	clone := sn.schnorr.Clone()

	// Key the clone with the signer's private key.
	clone.KEY(sn.d.Encode(buf[:0]))

	// Deterministically derive an ephemeral key pair from the cloned context.
	r := clone.PRFScalar()
	R := ristretto255.NewElement().ScalarBaseMult(r)

	// Hash the ephemeral public key.
	sn.schnorr.AD(R.Encode(buf[:0]))

	// Extract a challenge scalar from the protocol state.
	c := sn.schnorr.PRFScalar()

	// Calculate the signature scalar.
	s := ristretto255.NewScalar().Multiply(sn.d, c)
	s = s.Add(s, r)

	// Return the challenge and signature scalars.
	return s.Encode(c.Encode(buf[:0]))
}

// Verifier is an io.Writer which adds written data to a STROBE protocol for verification.
type Verifier struct {
	schnorr *protocol.Protocol
	q       *ristretto255.Element
}

// NewVerifier returns a Verifier instance with a signer's public key.
func NewVerifier(q *ristretto255.Element) *Verifier {
	// Initialize a new protocol.
	schnorr := protocol.New("veil.schnorr")

	// Add the signer's public key to the protocol.
	schnorr.AD(q.Encode(nil))

	// Prep it for streaming cleartext.
	schnorr.RecvCLR(nil)

	return &Verifier{schnorr: schnorr, q: q}
}

func (vr *Verifier) Write(p []byte) (n int, err error) {
	// Update the protocol with the written data.
	vr.schnorr.MoreRecvCLR(p)

	return len(p), nil
}

// Verify uses the given public key to verify the signature of the previously read data.
func (vr *Verifier) Verify(sig []byte) bool {
	var buf [internal.ElementSize]byte

	// Check signature length.
	if len(sig) != SignatureSize {
		return false
	}

	// Decode the challenge scalar.
	c := ristretto255.NewScalar()
	if err := c.Decode(sig[:internal.ScalarSize]); err != nil {
		return false
	}

	// Decode the signature scalar.
	s := ristretto255.NewScalar()
	if err := s.Decode(sig[internal.ScalarSize:]); err != nil {
		return false
	}

	// Re-calculate the ephemeral public key.
	S := ristretto255.NewElement().ScalarBaseMult(s)
	Qc := ristretto255.NewElement().ScalarMult(ristretto255.NewScalar().Negate(c), vr.q)
	Rp := ristretto255.NewElement().Add(S, Qc)

	// Hash the ephemeral public key.
	vr.schnorr.AD(Rp.Encode(buf[:0]))

	// Extract a challenge scalar from the protocol state.
	cp := vr.schnorr.PRFScalar()

	// Compare the extracted challenge scalar to the received challenge scalar.
	return c.Equal(cp) == 1
}

var (
	_ io.Writer = &Signer{}
	_ io.Writer = &Verifier{}
)

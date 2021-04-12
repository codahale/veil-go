// Package schnorr provides the underlying STROBE protocol for Veil's Schnorr signatures.
//
// Signing is as follows, given associated data D, a message in blocks M_0...M_n, a private scalar
// d, and a public element Q:
//
//     INIT('veil.schnorr', level=256)
//     AD(Q)
//     AD(D)
//     SEND_CLR('',  streaming=false)
//     SEND_CLR(M_0, streaming=true)
//     SEND_CLR(M_1, streaming=true)
//     ...
//     SEND_CLR(M_0, streaming=true)
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
//     SEND_ENC(R) -> S1
//     PRF(64) -> k
//     s = (kd + r)
//     SEND_ENC(s) -> S2
//
// The resulting signature consists of the encrypted ephemeral element S1 and the encrypted
// signature scalar S2.
//
// To verify, veil.schnorr is run with associated data D, message in blocks M_0...M_n, a public
// element Q, an encrypted ephemeral element S1, and an encrypted signature scalar S2:
//
//     INIT('veil.schnorr', level=256)
//     AD(Q)
//     AD(D)
//     RECV_CLR('',  streaming=false)
//     RECV_CLR(M_0, streaming=true)
//     RECV_CLR(M_1, streaming=true)
//     ...
//     RECV_CLR(M_0, streaming=true)
//     RECV_ENC(S1) -> R
//     PRF(64) -> k
//     RECV_ENC(S2) -> s
//     R' = -kQ + sG
//
// Finally, the verifier compares R' == R. If the two elements are equivalent, the signature is
// valid.
//
// This construction integrates message hashing with signature creation/validation, uses the
// sender's private key and the message to derive a challenge nonce, binds the signer's identity,
// and produces a signature which is indistinguishable from random noise without the signer's public
// key, the associated data, and the message.
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

// NewSigner returns a Signer instance with the signer's key pair and any associated data.
func NewSigner(d *ristretto255.Scalar, q *ristretto255.Element, associatedData []byte) *Signer {
	// Initialize a new protocol.
	schnorr := protocol.New("veil.schnorr")

	// Add the signer's public key to the protocol.
	schnorr.AD(q.Encode(nil))

	// Add the associated data to the protocol.
	schnorr.AD(associatedData)

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
	// Deterministically derive a nonce in a cloned context.
	r := sn.deriveNonce(sn.d)

	// Calculate the signature ephemeral.
	R := ristretto255.NewElement().ScalarBaseMult(r)

	// Encrypt the signature ephemeral.
	sigA := sn.schnorr.SendENC(nil, R.Encode(nil))

	// Derive a challenge value scalar.
	k := sn.schnorr.PRFScalar()

	// Calculate the signature scalar (kd + r).
	s := ristretto255.NewScalar().Multiply(k, sn.d)
	s = ristretto255.NewScalar().Add(s, r)

	// Encrypt the signature scalar.
	sigB := sn.schnorr.SendENC(nil, s.Encode(nil))

	// Return the encoding of R and the ciphertext of s as the signature.
	return append(sigA, sigB...)
}

func (sn *Signer) deriveNonce(d *ristretto255.Scalar) *ristretto255.Scalar {
	// Clone the protocol context. This step requires knowledge of the signer's private key, so it
	// can't be part of the verification process.
	clone := sn.schnorr.Clone()

	// Key the clone with the signer's private key.
	clone.KEY(d.Encode(nil))

	// Derive a nonce scalar.
	return clone.PRFScalar()
}

// Verifier is an io.Writer which adds written data to a STROBE protocol for verification.
type Verifier struct {
	schnorr *protocol.Protocol
	q       *ristretto255.Element
}

// NewVerifier returns a Verifier instance with a signer's public key and any associated data.
func NewVerifier(q *ristretto255.Element, associatedData []byte) *Verifier {
	// Initialize a new protocol.
	schnorr := protocol.New("veil.schnorr")

	// Add the signer's public key to the protocol.
	schnorr.AD(q.Encode(nil))

	// Add the associated data to the protocol.
	schnorr.AD(associatedData)

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
	// Check signature length.
	if len(sig) != SignatureSize {
		return false
	}

	// Split the signature.
	sigA, sigB := sig[:internal.ElementSize], sig[internal.ElementSize:]

	// Receive the signature ephemeral.
	sigA = vr.schnorr.RecvENC(nil, sigA)

	// Decode the signature ephemeral.
	R := ristretto255.NewElement()
	if err := R.Decode(sigA); err != nil {
		return false
	}

	// Derive a challenge scalar.
	k := vr.schnorr.PRFScalar()

	// Decrypt the signature scalar.
	sb := vr.schnorr.RecvENC(nil, sigB)

	// Decode the signature scalar.
	s := ristretto255.NewScalar()
	if err := s.Decode(sb); err != nil {
		return false
	}

	// R' = -kQ + sG
	ky := ristretto255.NewElement().ScalarMult(k, vr.q)
	Rp := ristretto255.NewElement().ScalarBaseMult(s)
	Rp = ristretto255.NewElement().Subtract(Rp, ky)

	return Rp.Equal(R) == 1
}

var (
	_ io.Writer = &Signer{}
	_ io.Writer = &Verifier{}
)

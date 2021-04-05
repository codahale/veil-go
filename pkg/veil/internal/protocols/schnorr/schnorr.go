// Package schnorr provides the underlying STROBE protocol for Veil's Schnorr signatures.
//
// Signing is as follows, given a message in blocks M_0...M_n, a private scalar d, and a public
// element Q:
//
//     INIT('veil.schnorr', level=256)
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
//     RATCHET(32)
//
// Once r is generated, the clone's context is discarded and r is returned to the parent context:
//
//     R = rG
//     SEND_CLR(Q)
//     SEND_CLR(R)
//     PRF(64) -> k
//     s = (kd + r)
//     SEND_ENC(s) -> S
//
// The resulting signature consists of the ephemeral element R and the encrypted signature scalar S.
//
// To verify, veil.schnorr is run with a message in blocks M_0...M_n, a public element Q, an
// ephemeral element R, and an encrypted signature scalar S:
//
//     INIT('veil.schnorr', level=256)
//     RECV_CLR('',  streaming=false)
//     RECV_CLR(M_0, streaming=true)
//     RECV_CLR(M_1, streaming=true)
//     ...
//     RECV_CLR(M_0, streaming=true)
//     RECV_CLR(Q)
//     RECV_CLR(R)
//     PRF(64) -> k
//     RECV_ENC(S) -> s
//     R' = -kQ + sG
//
// Finally, the verifier compares R' == R. If the two elements are equivalent, the signature is
// valid.
package schnorr

import (
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

const (
	SignatureSize = 64 // SignatureSize is the length of a signature in bytes.
)

// Signer is a pass-through io.Writer which adds written data to a STROBE protocol for signing.
type Signer struct {
	schnorr *strobe.Strobe
	dst     io.Writer
}

// NewSigner returns a Signer instance which passes writes through to dst.
func NewSigner(dst io.Writer) *Signer {
	// Initialize a new protocol.
	schnorr := protocols.New("veil.schnorr")

	// Prep it for streaming cleartext.
	protocols.Must(schnorr.SendCLR(nil, &strobe.Options{}))

	return &Signer{schnorr: schnorr, dst: dst}
}

func (sn *Signer) Write(p []byte) (n int, err error) {
	n, err = sn.dst.Write(p)
	if err != nil {
		return
	}

	// Transmit the written data to the protocol.
	protocols.Must(sn.schnorr.SendCLR(p[:n], &strobe.Options{Streaming: true}))

	return
}

// Sign uses the given key pair to construct a deterministic Schnorr signature of the previously
// written data.
func (sn *Signer) Sign(d *ristretto255.Scalar, q *ristretto255.Element) []byte {
	var (
		buf [r255.UniformBytestringSize]byte
		sig [SignatureSize]byte
	)

	// Deterministically derive a nonce in a cloned context.
	r := sn.deriveNonce(d)

	// Calculate the signature ephemeral.
	R := ristretto255.NewElement().ScalarBaseMult(r)
	sigA := R.Encode(sig[:0])

	// Transmit the signer's public key.
	protocols.Must(sn.schnorr.SendCLR(q.Encode(nil), &strobe.Options{}))

	// Transmit the signature ephemeral.
	protocols.Must(sn.schnorr.SendCLR(sigA, &strobe.Options{}))

	// Derive a challenge value.
	protocols.Must(sn.schnorr.PRF(buf[:], false))

	// Map the challenge value to a scalar.
	k := ristretto255.NewScalar().FromUniformBytes(buf[:])

	// Calculate the signature scalar (kd + r).
	s := ristretto255.NewScalar().Multiply(k, d)
	s = ristretto255.NewScalar().Add(s, r)

	// Encrypt the signature scalar.
	sigB := s.Encode(sig[r255.ElementSize:r255.ElementSize])
	protocols.MustENC(sn.schnorr.SendENC(sigB, &strobe.Options{}))

	// Return the encoding of R and the ciphertext of s as the signature.
	return sig[:]
}

func (sn *Signer) deriveNonce(d *ristretto255.Scalar) *ristretto255.Scalar {
	var buf [r255.UniformBytestringSize]byte

	// Clone the protocol context. This step requires knowledge of the signer's private key, so it
	// can't be part of the verification process.
	clone := sn.schnorr.Clone()

	// Key the clone with the signer's private key.
	protocols.Must(clone.KEY(d.Encode(nil), false))

	// Derive a nonce.
	protocols.Must(clone.PRF(buf[:], false))

	// Ratchet the protocol.
	protocols.Must(clone.RATCHET(protocols.RatchetSize))

	// Map the nonce to a scalar.
	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

// Verifier is a pass-through io.Reader which adds read data to a STROBE protocol for verification.
type Verifier struct {
	schnorr *strobe.Strobe
	src     io.Reader
}

// NewVerifier returns a Verifier instance which passes reads through to src.
func NewVerifier(src io.Reader) *Verifier {
	// Initialize a new protocol.
	schnorr := protocols.New("veil.schnorr")

	// Prep it for streaming cleartext.
	protocols.Must(schnorr.RecvCLR(nil, &strobe.Options{}))

	return &Verifier{schnorr: schnorr, src: src}
}

func (vr *Verifier) Read(p []byte) (n int, err error) {
	n, err = vr.src.Read(p)
	if err != nil {
		return
	}

	protocols.Must(vr.schnorr.RecvCLR(p[:n], &strobe.Options{Streaming: true}))

	return
}

// Verify uses the given public key to verify the signature of the previously read data.
func (vr *Verifier) Verify(q *ristretto255.Element, sig []byte) bool {
	var buf [r255.UniformBytestringSize]byte

	// Check signature length.
	if len(sig) != SignatureSize {
		return false
	}

	// Split the signature.
	sigA, sigB := sig[:r255.ElementSize], sig[r255.ElementSize:]

	// Decode the signature ephemeral.
	R := ristretto255.NewElement()
	if err := R.Decode(sigA); err != nil {
		return false
	}

	// Receive the signer's public key.
	protocols.Must(vr.schnorr.RecvCLR(q.Encode(nil), &strobe.Options{}))

	// Receive the signature ephemeral.
	protocols.Must(vr.schnorr.RecvCLR(sigA, &strobe.Options{}))

	// Derive a challenge value.
	protocols.Must(vr.schnorr.PRF(buf[:], false))

	// Map the challenge value to a scalar.
	k := ristretto255.NewScalar().FromUniformBytes(buf[:])

	// Copy the encrypted signature scalar.
	sb := make([]byte, len(sigB))
	copy(sb, sigB)

	// Decrypt the signature scalar.
	protocols.MustENC(vr.schnorr.RecvENC(sb, &strobe.Options{}))

	// Decode the signature scalar.
	s := ristretto255.NewScalar()
	if err := s.Decode(sb); err != nil {
		return false
	}

	// R' = -kQ + sG
	ky := ristretto255.NewElement().ScalarMult(k, q)
	Rp := ristretto255.NewElement().ScalarBaseMult(s)
	Rp = ristretto255.NewElement().Subtract(Rp, ky)

	return Rp.Equal(R) == 1
}

var (
	_ io.Writer = &Signer{}
	_ io.Reader = &Verifier{}
)

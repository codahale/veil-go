// Package schnorr provides the underlying STROBE protocol for Veil's Schnorr signatures.
//
// Signing is as follows, given a message in blocks M_0…M_n, a private scalar d, and a public
// element Q:
//
//     INIT('veil.schnorr', level=256)
//     AD(Q)
//     SEND_CLR('',  more=false)
//     SEND_CLR(M_0, more=true)
//     SEND_CLR(M_1, more=true)
//     …
//     SEND_CLR(M_n, more=true)
//
// The protocol's state is then cloned, the clone is keyed with 64 bytes of random data and the
// signer's private key, an ephemeral scalar is derived from PRF output:
//
//     KEY(rand(64))
//     KEY(d)
//     PRF(64) -> r
//
// The clone's state is discarded, and r is returned to the parent:
//
//     R = G^r
//     AD(R)
//     PRF(64) -> c
//     s = d_s*c + r
//
// The resulting signature consists of the two scalars, c and s.
//
// To verify, veil.schnorr is run with associated data D, message in blocks M_0…M_n, a public
// element Q:
//
//     INIT('veil.schnorr', level=256)
//     AD(Q)
//     RECV_CLR('',  more=false)
//     RECV_CLR(M_0, more=true)
//     RECV_CLR(M_1, more=true)
//     …
//     RECV_CLR(M_n, more=true)
//     R' = Q^-c + G^s
//     AD(R')
//     PRF(64) -> c'
//
// Finally, the verifier compares c' == c. If the two scalars are equivalent, the signature is
// valid.
//
// Indistinguishability and Pseudorandomness
//
// This construction integrates message hashing with signature creation/validation, binds the
// signer's identity, and produces indistinguishable signatures (i.e., signatures which do not
// reveal anything about the signing key or signed message). When encrypted with an unrelated key
// (i.e., via veil.mres), the construction is isomorphic to Fleischhacker et al.'s DRPC compiler for
// producing pseudorandom signatures (https://eprint.iacr.org/2011/673.pdf), which are
// indistinguishable from random.
//
// Ephemeral Scalar Hedging
//
// In deriving the ephemeral scalar from a cloned context, veil.schnorr uses Aranha et al.'s "hedged
// signature" technique (https://eprint.iacr.org/2019/956.pdf) to mitigate against both catastrophic
// randomness failures and differential fault attacks against purely deterministic signature
// schemes.
package schnorr

import (
	"crypto/rand"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
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

	io.Writer
}

// NewSigner returns a Signer instance with the signer's key pair.
func NewSigner(d *ristretto255.Scalar, q *ristretto255.Element) *Signer {
	// Initialize a new protocol.
	schnorr := protocol.New("veil.schnorr")

	// Add the signer's public key to the protocol.
	schnorr.AD(q.Encode(nil))

	return &Signer{schnorr: schnorr, d: d, Writer: schnorr.SendCLRStream(io.Discard)}
}

// Sign uses the given key pair to construct a Schnorr signature of the previously written data.
func (sn *Signer) Sign() ([]byte, error) {
	var buf [SignatureSize]byte

	// Clone the protocol.
	clone := sn.schnorr.Clone()

	// Generate a random nonce.
	if _, err := rand.Read(buf[:internal.UniformBytestringSize]); err != nil {
		return nil, err
	}

	// Key the clone with the nonce.
	clone.KEY(buf[:internal.UniformBytestringSize])

	// Key the clone with the signer's private key.
	clone.KEY(sn.d.Encode(buf[:0]))

	// Derive an ephemeral key pair from the clone.
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
	return s.Encode(c.Encode(buf[:0])), nil
}

// Verifier is an io.Writer which adds written data to a STROBE protocol for verification.
type Verifier struct {
	schnorr *protocol.Protocol
	q       *ristretto255.Element

	io.Writer
}

// NewVerifier returns a Verifier instance with a signer's public key.
func NewVerifier(q *ristretto255.Element) *Verifier {
	// Initialize a new protocol.
	schnorr := protocol.New("veil.schnorr")

	// Add the signer's public key to the protocol.
	schnorr.AD(q.Encode(nil))

	return &Verifier{schnorr: schnorr, q: q, Writer: schnorr.RecvCLRStream(io.Discard)}
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

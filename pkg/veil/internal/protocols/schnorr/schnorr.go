// Package schnorr provides the underlying STROBE protocol for Veil's Schnorr signatures.
//
// Signing is as follows, given a private scalar d, its public element Q, and a message M. First, a
// deterministic nonce r is derived from the private key and message:
//
//     INIT('veil.schnorr.nonce', level=256)
//     AD(M)
//     KEY(d)
//     PRF(64) -> r
//
// Given the nonce r, its public element R = rG is calculated, a second protocol is run:
//
//     INIT('veil.schnorr', level=256)
//     AD(M)
//     AD(Q)
//     SEND_CLR(R)
//     PRF(64) -> k
//     s = (kd + r)
//     SEND_ENC(s) -> S
//
// The resulting signature consists of the ephemeral element R and the encrypted signature scalar S.
//
// To verify, veil.schnorr is run with a public key Q, an ephemeral element R, an encrypted
// signature scalar S, and a candidate message M:
//
//     INIT('veil.schnorr', level=256)
//     AD(M)
//     AD(Q)
//     RECV_CLR(R)
//     PRF(64) -> k
//     RECV_ENC(S) -> s
//     R' = -kQ + sG
//
// Finally, the verifier compares R' == R. If the two points are equivalent, the signature is valid.
package schnorr

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

const (
	SignatureSize = 64 // SignatureSize is the length of a signature in bytes.
)

// Sign uses the given key pair to construct a deterministic Schnorr signature of the given message.
func Sign(d *ristretto255.Scalar, q *ristretto255.Element, msg []byte) []byte {
	var (
		buf [r255.UniformBytestringSize]byte
		sig [SignatureSize]byte
	)

	// Deterministically derive a nonce via veil.schnorr.nonce.
	r := deriveNonce(d, msg)

	// Calculate the signature ephemeral.
	R := ristretto255.NewElement().ScalarBaseMult(r)
	sigA := R.Encode(sig[:0])

	// Initialize the veil.schnorr protocol.
	schnorr := protocols.New("veil.schnorr")

	// Include the message as associated data.
	protocols.Must(schnorr.AD(msg, &strobe.Options{}))

	// Add the sender's public key as associated data.
	protocols.Must(schnorr.AD(q.Encode(nil), &strobe.Options{}))

	// Transmit the signature ephemeral.
	protocols.Must(schnorr.SendCLR(sigA, &strobe.Options{}))

	// Derive a challenge value.
	protocols.Must(schnorr.PRF(buf[:], false))

	// Map the challenge value to a scalar.
	k := ristretto255.NewScalar().FromUniformBytes(buf[:])

	// Calculate the signature scalar (kd + r).
	s := ristretto255.NewScalar().Multiply(k, d)
	s = ristretto255.NewScalar().Add(s, r)

	// Encrypt the signature scalar.
	sigB := s.Encode(sig[r255.ElementSize:r255.ElementSize])
	protocols.MustENC(schnorr.SendENC(sigB, &strobe.Options{}))

	// Return the encoding of R and the ciphertext of s as the signature.
	return sig[:]
}

// Verify uses the given public key to verify the two-part signature of the given candidate message.
func Verify(q *ristretto255.Element, sig, msg []byte) bool {
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

	schnorr := protocols.New("veil.schnorr")

	// Include the message as associated data.
	protocols.Must(schnorr.AD(msg, &strobe.Options{}))

	// Include the sender's public key as associated data.
	protocols.Must(schnorr.AD(q.Encode(nil), &strobe.Options{}))

	// Receive the signature ephemeral.
	protocols.Must(schnorr.RecvCLR(sigA, &strobe.Options{}))

	// Derive a challenge value.
	protocols.Must(schnorr.PRF(buf[:], false))

	// Map the challenge value to a scalar.
	k := ristretto255.NewScalar().FromUniformBytes(buf[:])

	// Copy the encrypted signature scalar.
	sb := make([]byte, len(sigB))
	copy(sb, sigB)

	// Decrypt the signature scalar.
	protocols.MustENC(schnorr.RecvENC(sb, &strobe.Options{}))

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

func deriveNonce(d *ristretto255.Scalar, msg []byte) *ristretto255.Scalar {
	var buf [r255.UniformBytestringSize]byte

	nonce := protocols.New("veil.schnorr.nonce")

	// Include the message as associated data.
	protocols.Must(nonce.AD(msg, &strobe.Options{}))

	// Key the clone with the signer's private key.
	protocols.Must(nonce.KEY(d.Encode(nil), false))

	// Derive a nonce.
	protocols.Must(nonce.PRF(buf[:], false))

	// Map the nonce to a scalar.
	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

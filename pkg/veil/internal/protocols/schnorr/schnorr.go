// Package schnorr provides the underlying STROBE protocol for Veil's Schnorr signatures.
//
// Signing is as follows, given a private scalar D, its public point Q, and a message M. First, a
// deterministic nonce r is derived from the private key and message:
//
//     INIT('veil.schnorr.nonce', level=256)
//     AD(M)
//     KEY(D)
//     PRF(64) -> r
//
// Given the nonce r, its public point R = gr is calculated, a second protocol re-run:
//
//     INIT('veil.schnorr', level=256)
//     AD(M)
//     AD(Q)
//     SEND_CLR(R)
//     PRF(64) -> k
//     s = (kd + r)
//     SEND_ENC(s)
//
// The resulting signature consists of the ephemeral point R and the encrypted signature scalar S.
//
// To verify, veil.schnorr is run with a public key Q, an ephemeral point R, an encrypted signature
// scalar S, and a candidate message M:
//
//     INIT('veil.schnorr', level=256)
//     AD(M)
//     AD(Q)
//     RECV_CLR(R)
//     PRF(64) -> k
//     RECV_ENC(S)
//
// Finally, the verifier calculates R' = -kQ + gs and compares R' == R.
package schnorr

import (
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// Sign uses the given key pair to construct a deterministic Schnorr signature of the given message.
func Sign(d *ristretto255.Scalar, q *ristretto255.Element, msg []byte) ([]byte, []byte) {
	var buf [64]byte

	// Deterministically derive a nonce via veil.schnorr.nonce.
	r := deriveNonce(d, msg)

	// Calculate the signature ephemeral.
	R := ristretto255.NewElement().ScalarBaseMult(r)
	sigA := R.Encode(nil)

	// Initialize the veil.schnorr protocol.
	schnorr, err := strobe.New("veil.schnorr", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	// Include the message as associated data.
	if err := schnorr.AD(msg, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Add the sender's public key as associated data.
	if err := schnorr.AD(q.Encode(nil), &strobe.Options{}); err != nil {
		panic(err)
	}

	// Transmit the signature ephemeral.
	if err := schnorr.SendCLR(sigA, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Derive a challenge value.
	if err := schnorr.PRF(buf[:], false); err != nil {
		panic(err)
	}

	// Map the challenge value to a scalar.
	k := ristretto255.NewScalar().FromUniformBytes(buf[:])

	// Calculate the signature scalar (kd + r).
	s := ristretto255.NewScalar().Multiply(k, d)
	s = ristretto255.NewScalar().Add(s, r)

	// Encrypt the signature scalar.
	sigB := s.Encode(nil)
	if _, err := schnorr.SendENC(sigB, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Return the encoding of R and the ciphertext of s as the signature.
	return sigA, sigB
}

// Verify uses the given public key to verify the two-part signature of the given candidate message.
func Verify(q *ristretto255.Element, sigA, sigB, msg []byte) bool {
	var buf [64]byte

	// Decode the signature ephemeral.
	R := ristretto255.NewElement()
	if err := R.Decode(sigA); err != nil {
		return false
	}

	schnorr, err := strobe.New("veil.schnorr", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	// Include the message as associated data.
	if err := schnorr.AD(msg, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Include the sender's public key as associated data.
	if err := schnorr.AD(q.Encode(nil), &strobe.Options{}); err != nil {
		panic(err)
	}

	// Receive the signature ephemeral.
	if err := schnorr.RecvCLR(sigA, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Derive a challenge value.
	if err := schnorr.PRF(buf[:], false); err != nil {
		panic(err)
	}

	// Map the challenge value to a scalar.
	k := ristretto255.NewScalar().FromUniformBytes(buf[:])

	// Copy the encrypted signature scalar.
	sb := make([]byte, len(sigB))
	copy(sb, sigB)

	// Decrypt the signature scalar.
	if _, err := schnorr.RecvENC(sb, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Decode the signature scalar.
	s := ristretto255.NewScalar()
	if err := s.Decode(sb); err != nil {
		return false
	}

	// R' = -kQ + gs
	ky := ristretto255.NewElement().ScalarMult(k, q)
	Rp := ristretto255.NewElement().ScalarBaseMult(s)
	Rp = ristretto255.NewElement().Subtract(Rp, ky)

	return Rp.Equal(R) == 1
}

func deriveNonce(d *ristretto255.Scalar, msg []byte) *ristretto255.Scalar {
	var buf [64]byte

	nonce, err := strobe.New("veil.schnorr.nonce", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	// Include the message as associated data.
	if err := nonce.AD(msg, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Key the clone with the signer's private key.
	if err := nonce.KEY(d.Encode(nil), false); err != nil {
		panic(err)
	}

	// Derive a nonce.
	if err := nonce.PRF(buf[:], false); err != nil {
		panic(err)
	}

	// Map the nonce to a scalar.
	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

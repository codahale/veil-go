// Package xdh provides ristretto255/XDH functionality.
//
// Veil uses ristretto255 for asymmetric cryptography. Each person has a ristretto255/XDH key pair
// and shares their public key with each other. In place of encoded ristretto255 points, Veil
// encodes all public keys using Elligator2, making them indistinguishable from noise.
package xdh

import (
	"crypto/rand"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
)

const (
	PublicKeySize = 32                            // PublicKeySize is the length of a public key in bytes.
	SecretKeySize = 32                            // SecretKeySize is the length of a secret key in bytes.
	SignatureSize = PublicKeySize + SecretKeySize // SignatureSize is the length of a signature in bytes.
)

// SharedSecret performs a Diffie-Hellman key exchange using the given public key.
func SharedSecret(sk, pk []byte) []byte {
	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	parseScalar(&s, sk)
	parsePoint(&q, pk)

	// Multiply the point by the scalar.
	x := (&ristretto.Point{}).ScalarMult(&q, &s)

	// Return the shared secret.
	return x.Bytes()
}

// PublicKey returns the corresponding public key for the given secret key.
func PublicKey(sk []byte) []byte {
	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	// Decode the secret key.
	parseScalar(&s, sk)

	// Calculate the public key.
	q.ScalarMultBase(&s)

	// Encode the public key with Elligator2.
	return elligator(&q)
}

// GenerateKeys generates a key pair and returns the public key and the secret key.
func GenerateKeys() (pk, sk []byte, err error) {
	var (
		buf [64]byte
		s   ristretto.Scalar
		q   ristretto.Point
	)

	// Not all key pairs have public keys which can be represented by Elligator2, so try until we
	// find one.
	for pk == nil {
		// Generate 64 random bytes.
		if _, err = rand.Read(buf[:]); err != nil {
			return
		}

		// Convert to a secret key.
		s.SetReduced(&buf)

		// Encode the secret key.
		sk = s.Bytes()

		// Calculate the public key.
		q.ScalarMultBase(&s)

		// Encode the public key with Elligator2, if possible.
		pk = elligator(&q)
	}

	// We generated a secret key whose public key has a representative, so return them.
	return
}

// Sign returns a Schnorr signature of the given message using the given secret key.
func Sign(sk, message []byte) ([]byte, error) {
	var (
		skS, skE ristretto.Scalar
		c        ristretto.Scalar
		t        ristretto.Scalar
	)

	// Generate an ephemeral key pair.
	pkE, skEb, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	// Decode the static and ephemeral secret keys.
	parseScalar(&skS, sk)
	parseScalar(&skE, skEb)

	// Derive a scalar from the ephemeral public key and the message using SHA-512.
	c.Derive(append(pkE, message...))

	// Calculate the signature scalar.
	t.MulAdd(&c, &skS, &skE)

	// Return the ephemeral public key and the signature scalar.
	return append(pkE, t.Bytes()...), nil
}

// Verify returns true if the given signature of the given message was created with the secret key
// corresponding to the given public key.
func Verify(pk, message, sig []byte) bool {
	var (
		pkS ristretto.Point
		pkE ristretto.Point
		t   ristretto.Scalar
		c   ristretto.Scalar
		lhs ristretto.Point
		rhs ristretto.Point
	)

	if len(sig) != SignatureSize {
		return false
	}

	// Parse the static public key.
	parsePoint(&pkS, pk)

	// Parse the ephemeral public key.
	parsePoint(&pkE, sig[:32])

	// Parse the signature scalar.
	_ = t.UnmarshalBinary(sig[32:])

	// Derive a scalar from the ephemeral public key and the message.
	c.Derive(append(sig[:32], message...))

	// Calculate the left-hand side of the equation.
	lhs.ScalarMultBase(&t)

	// Calculate the right-hand side of the equation.
	rhs.ScalarMult(&pkS, &c).Add(&rhs, &pkE)

	// The signature is verified if both sides of the equation are equal.
	return lhs.Equals(&rhs)
}

// elligator encodes the given ristretto255 point using Elligator2, returning either 32 bytes of
// uniformly-distributed data or nil, if the point is not representable with Elligator2.
func elligator(q *ristretto.Point) []byte {
	var fes [8]edwards25519.FieldElement

	// Convert the public key to an extended point.
	qep := (*edwards25519.ExtendedPoint)(q)

	// Generate the 0 to 8 possible Elligator2 representatives.
	mask := qep.RistrettoElligator2Inverse(&fes)

	// Iterate through the possible representatives.
	for i := 0; i < 8; i++ {
		// Skip those possibilities don't exist.
		if ((1 << uint(i)) & mask) == 0 {
			continue
		}

		// Convert the first representative to bytes.
		rk := fes[i].Bytes()

		// Return the first representative.
		return rk[:]
	}

	// If no representative could be created, return nil.
	return nil
}

// parseScalar decodes the given bytes into the given ristretto255 scalar.
func parseScalar(s *ristretto.Scalar, sk []byte) {
	var buf [SecretKeySize]byte

	copy(buf[:], sk)

	s.SetBytes(&buf)
}

// parsePoint decodes the given Elligator2 bytes into the given ristretto255 point.
func parsePoint(q *ristretto.Point, pk []byte) {
	var (
		buf [PublicKeySize]byte
		fe  edwards25519.FieldElement
		cp  edwards25519.CompletedPoint
		ep  edwards25519.ExtendedPoint
	)

	// Copy the representative.
	copy(buf[:], pk)

	// Convert it to a field element.
	fe.SetBytes(&buf)

	// Convert the Elligator2 field element to a completed point.
	cp.SetRistrettoElligator2(&fe)

	// Convert the completed point to an extended point.
	ep.SetCompleted(&cp)

	// Set the output to the extended point.
	*q = (ristretto.Point)(ep)
}

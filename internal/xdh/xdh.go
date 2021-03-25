package xdh

import (
	"crypto/rand"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
)

// PublicKeySize is the length of an Elligator2 representative in bytes.
const PublicKeySize = 32

// SharedSecret performs a Diffie-Hellman key exchange using the given secret key and public key.
func SharedSecret(s *ristretto.Scalar, q *ristretto.Point) []byte {
	// Multiply the point by the scalar.
	x := (&ristretto.Point{}).ScalarMult(q, s)

	// Return the shared secret.
	return x.Bytes()
}

// RepresentativeToPublic converts a representative to a public key.
func RepresentativeToPublic(q *ristretto.Point, rk []byte) {
	var (
		buf [PublicKeySize]byte
		fe  edwards25519.FieldElement
		cp  edwards25519.CompletedPoint
		ep  edwards25519.ExtendedPoint
	)

	// Copy the representative.
	copy(buf[:], rk)

	// Convert it to a field element.
	fe.SetBytes(&buf)

	// Convert the Elligator2 field element to a completed point.
	cp.SetRistrettoElligator2(&fe)

	// Convert the completed point to an extended point.
	ep.SetCompleted(&cp)

	// Cast the extended point as a regular point.
	*q = (ristretto.Point)(ep)
}

// PublicToRepresentative converts a public key to an Elligator2 representative, if possible.
func PublicToRepresentative(q *ristretto.Point) []byte {
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

// SecretToPublic converts a secret key to a public key.
func SecretToPublic(q *ristretto.Point, s *ristretto.Scalar) {
	// Multiply the scalar by the curve base to produce the public key.
	q.ScalarMultBase(s)
}

// GenerateKeys generates a key pair and returns the public key, the public key's representative,
// and the secret key.
func GenerateKeys() (q ristretto.Point, rk []byte, s ristretto.Scalar, err error) {
	var buf [64]byte

	// Not all key pairs have public keys which can be represented by Elligator2, so try until we
	// find one.
	for rk == nil {
		// Generate 64 random bytes.
		if _, err = rand.Read(buf[:]); err != nil {
			return
		}

		// Convert to a secret key.
		s.SetReduced(&buf)

		// Generate the corresponding public key.
		SecretToPublic(&q, &s)

		// Calculate the public key's representative, if any.
		rk = PublicToRepresentative(&q)
	}

	// We generated a secret key whose public key has a representative, so return them.
	return
}

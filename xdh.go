package veil

import (
	"errors"
	"io"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
)

var (
	errNoRepresentative = errors.New("no representative")
	errInvalidExchange  = errors.New("invalid exchange")
)

// xdh performs a Diffie-Hellman key exchange using the given secret key and public key.
func xdh(s *ristretto.Scalar, q *ristretto.Point) ([]byte, error) {
	var (
		x    ristretto.Point
		zero ristretto.Point
	)

	// Multiply the point by the scalar.
	x.ScalarMult(q, s)

	// Initialize a zero point.
	zero.SetZero()

	// Check to see that the shared secret point is not zero.
	if x.Equals(&zero) {
		return nil, errInvalidExchange
	}

	// Return the shared secret.
	return x.Bytes(), nil
}

// rk2pk converts an Elligator2 representative to a public key.
func rk2pk(rk []byte) ristretto.Point {
	var (
		buf [32]byte
		fe  edwards25519.FieldElement
		cp  edwards25519.CompletedPoint
		ep  edwards25519.ExtendedPoint
	)

	// Copy the representative.
	copy(buf[:], rk)

	// Convert it to a field element.
	fe.SetBytes(&buf)

	// Convert the Elligator field element to a completed point.
	cp.SetRistrettoElligator2(&fe)

	// Convert the completed point to an extended point.
	ep.SetCompleted(&cp)

	// Cast the extended point as a result point.
	q := ristretto.Point(ep)

	// Return the public key.
	return q
}

// pk2rk converts a public key to an Elligator2 representative, if possible.
func pk2rk(q *ristretto.Point) ([]byte, error) {
	var fes [8]edwards25519.FieldElement

	// Convert the public key to an extended point.
	qep := (*edwards25519.ExtendedPoint)(q)

	// Generate the 0 to 8 possible Elligator2 representatives.
	mask := qep.RistrettoElligator2Inverse(&fes)

	// Iterate through the possible representatives.
	for i := 0; i < 8; i++ {
		// Skip those possibilities which are unrepresentable.
		if ((1 << uint(i)) & mask) == 0 {
			continue
		}

		// Convert the first representative to bytes.
		rk := fes[i].Bytes()

		// Return the public key and its representative.
		return rk[:], nil
	}

	// If no representative was generated, return an error.
	return nil, errNoRepresentative
}

// sk2pk converts a secret key to a public key.
func sk2pk(s *ristretto.Scalar) ristretto.Point {
	var q ristretto.Point

	// Multiply the scalar by the curve base to produce the public key.
	q.ScalarMultBase(s)

	return q
}

// ephemeralKeys generate an Ristretto255/DH key pair and returns the public key, the Elligator2
// representative of the public key, and the secret key.
func ephemeralKeys(rand io.Reader) (q ristretto.Point, rk []byte, s ristretto.Scalar, err error) {
	var buf [32]byte

	// Not all key pairs can be represented by Elligator2, so try until we find one.
	for {
		// Generate 32 random bytes.
		if _, err = io.ReadFull(rand, buf[:]); err != nil {
			return
		}

		// Convert to a Ristretto255/DH secret key.
		s.SetBytes(&buf)

		// Generate the corresponding public key.
		q = sk2pk(&s)

		// Calculate the public key's Elligator2 representative, if any.
		rk, err = pk2rk(&q)
		if err != nil {
			// If the public key doesn't have an Elligator2 representative, try again.
			continue
		}

		// Otherwise, return the values.
		return
	}
}

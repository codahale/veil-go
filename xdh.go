package veil

import (
	"errors"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
)

var (
	errNoRepresentative = errors.New("no representative")
	errInvalidExchange  = errors.New("invalid exchange")
)

// xdh performs a Diffie-Hellman key exchange using the given secret key and public key.
func xdh(sk, pk []byte) ([]byte, error) {
	var (
		buf  [32]byte
		s    ristretto.Scalar
		q    ristretto.Point
		x    ristretto.Point
		zero ristretto.Point
	)

	// Initialize a zero point.
	zero.SetZero()

	// Copy the secret key.
	copy(buf[:], sk)

	// Initialize the scalar with the secret key.
	s.SetBytes(&buf)

	// Copy the public key.
	copy(buf[:], pk)

	// Initialize the point with the public key.
	q.SetBytes(&buf)

	// Multiply the point by the scalar.

	x.ScalarMult(&q, &s)

	// Check to see that the shared secret point is not zero.
	if x.Equals(&zero) {
		return nil, errInvalidExchange
	}

	// Return the shared secret.
	return x.Bytes(), nil
}

// rk2pk converts an Elligator2 representative to a public key.
func rk2pk(rk []byte) []byte {
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
	return q.Bytes()
}

// sk2pkrk converts a secret key to a public key and its Elligator2 representative.
func sk2pkrk(sk []byte) ([]byte, []byte, error) {
	var (
		buf [32]byte
		s   ristretto.Scalar
		q   ristretto.Point
		fes [8]edwards25519.FieldElement
	)

	// Copy the secret key.
	copy(buf[:], sk)

	// Convert the secret key to a scalar.
	s.SetBytes(&buf)

	// Multiply the scalar by the curve base to produce the public key.
	q.ScalarMultBase(&s)

	// Convert the public key to an extended point.
	qep := edwards25519.ExtendedPoint(q)

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
		return q.Bytes(), rk[:], nil
	}

	// If no representative was generated, return an error.
	return nil, nil, errNoRepresentative
}

// sk2pk converts a secret key to a public key.
func sk2pk(sk []byte) []byte {
	var (
		buf [32]byte
		s   ristretto.Scalar
		q   ristretto.Point
	)

	// Copy the secret key.
	copy(buf[:], sk)

	// Convert the secret key to a scalar.
	s.SetBytes(&buf)

	// Multiply the scalar by the curve base to produce the public key.
	q.ScalarMultBase(&s)

	// Return the public key.
	return q.Bytes()
}

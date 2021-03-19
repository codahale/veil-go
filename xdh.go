package veil

import (
	"errors"
	"io"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
)

var (
	// errNoRepresentative is returned when a Ristretto255 point has no Elligator2 representative.
	errNoRepresentative = errors.New("no representative")

	// errInvalidExchange is returned when a Ristretto255/DH shared secret point is zero. This
	// should never happen.
	errInvalidExchange = errors.New("invalid exchange")
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

const (
	// The length of an Elligator2 representative for a Ristretto255 public key.
	kemPublicKeyLen = 32
	kemOverhead     = kemPublicKeyLen + poly1305.TagSize // Total overhead of KEM envelope.
)

// kemSend generates an ephemeral Elligator2 representative, a symmetric key, and a nonce given the
// sender's secret key, the sender's public key, and the recipient's public key. Also includes
// any authenticated data.
func kemSend(
	rand io.Reader, skS *ristretto.Scalar, pkS, pkR *ristretto.Point, data []byte,
) ([]byte, []byte, []byte, error) {
	// Generate an ephemeral Ristretto255/DH key pair.
	_, rkE, skE, err := ephemeralKeys(rand)
	if err != nil {
		return nil, nil, nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the ephemeral secret key and the
	// recipient's Ristretto255/DH public key.
	zzE, err := xdh(&skE, pkR)
	if err != nil {
		return nil, nil, nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the sender's secret key and the
	// recipient's Ristretto255/DH public key.
	zzS, err := xdh(skS, pkR)
	if err != nil {
		return nil, nil, nil, err
	}

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key and nonce from the shared secret, the authenticated data, the ephemeral public
	// key's Elligator2 representative, and the public keys of both the recipient and the sender.
	key, nonce := kdf(zz, data, rkE, pkR, pkS)

	return rkE, key, nonce, nil
}

// kemReceive generates a symmetric key and a nonce given the recipient's secret key, the
// recipient's public key, the sender's public key, the ephemeral Elligator2 representative, and
// any authenticated data.
func kemReceive(skR *ristretto.Scalar, pkR, pkS *ristretto.Point, rkE, data []byte) ([]byte, []byte, error) {
	// Convert the embedded Elligator2 representative to a Ristretto255/DH public key.
	pkE := rk2pk(rkE)

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the
	// ephemeral public key.
	zzE, err := xdh(skR, &pkE)
	if err != nil {
		return nil, nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the
	// sender's public key.
	zzS, err := xdh(skR, pkS)
	if err != nil {
		return nil, nil, err
	}

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key from the shared secret, the authenticated data, the ephemeral public key's
	// Elligator2 representative, and the public keys of both the recipient and sender.
	key, nonce := kdf(zz, data, rkE, pkR, pkS)

	return key, nonce, nil
}

// kdf returns a ChaCha20Poly1305 key and nonce derived from the given initial keying material, the
// authenticated data, the Elligator2 representative of the ephemeral key, the recipient's public
// key, and the sender's public key.
func kdf(ikm, data, rkE []byte, pkR, pkS *ristretto.Point) ([]byte, []byte) {
	// Create a salt consisting of the Elligator2 representative of the ephemeral key, the
	// recipient's public key, and the sender's public key.
	salt := make([]byte, 0, len(rkE)*3)
	salt = append(salt, rkE...)
	salt = append(salt, pkR.Bytes()...)
	salt = append(salt, pkS.Bytes()...)

	// Create an HKDF-SHA-256 instance from the initial keying material, the salt, and the
	// authenticated data.
	h := hkdf.New(sha3.New512, ikm, salt, data)

	// Derive the key from the HKDF output.
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, key)

	// Derive the nonce from the HKDF output.
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, _ = io.ReadFull(h, nonce)

	return key, nonce
}

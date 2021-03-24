package veil

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
	"golang.org/x/crypto/hkdf"
)

// xdh performs a Diffie-Hellman key exchange using the given secret key and public key.
func xdh(s *ristretto.Scalar, q *ristretto.Point) []byte {
	// Multiply the point by the scalar.
	x := (&ristretto.Point{}).ScalarMult(q, s)

	// Return the shared secret.
	return x.Bytes()
}

// rk2pk converts a representative to a public key.
func rk2pk(q *ristretto.Point, rk []byte) {
	var (
		buf [kemRepSize]byte
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

// pk2rk converts a public key to an Elligator2 representative, if possible.
func pk2rk(q *ristretto.Point) []byte {
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

// sk2pk converts a secret key to a public key.
func sk2pk(q *ristretto.Point, s *ristretto.Scalar) {
	// Multiply the scalar by the curve base to produce the public key.
	q.ScalarMultBase(s)
}

// generateKeys generates a key pair and returns the public key, the public key's representative,
// and the secret key.
func generateKeys() (q ristretto.Point, rk []byte, s ristretto.Scalar, err error) {
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
		sk2pk(&q, &s)

		// Calculate the public key's representative, if any.
		rk = pk2rk(&q)
	}

	// We generated a secret key whose public key has a representative, so return them.
	return
}

const (
	kemRepSize  = 32                        // The length of an Elligator2 representative.
	kemOverhead = kemRepSize + aeadOverhead // Total overhead of KEM envelope.
)

// kemSend generates an ephemeral representative, a symmetric key, and an IV given the sender's
// secret key, the sender's public key, and the recipient's public key.
func kemSend(skS *ristretto.Scalar, pkS, pkR *ristretto.Point, header bool) ([]byte, []byte, []byte, error) {
	// Generate an ephemeral key pair.
	_, rkE, skE, err := generateKeys()
	if err != nil {
		return nil, nil, nil, err
	}

	// Calculate the ephemeral shared secret between the ephemeral secret key and the recipient's
	// public key.
	zzE := xdh(&skE, pkR)

	// Calculate the static shared secret between the sender's secret key and the recipient's
	// public key.
	zzS := xdh(skS, pkR)

	// Derive the key and IV from the shared secrets, the ephemeral public key's representative, and
	// the public keys of both the recipient and the sender.
	key, iv := kdf(zzE, zzS, rkE, pkR, pkS, header)

	// Return the ephemeral public key's representative, the symmetric key, and the IV.
	return rkE, key, iv, nil
}

// kemReceive generates a symmetric key and IV given the recipient's secret key, the recipient's
// public key, the sender's public key, and the ephemeral representative.
func kemReceive(skR *ristretto.Scalar, pkR, pkS *ristretto.Point, rkE []byte, header bool) ([]byte, []byte) {
	var pkE ristretto.Point

	// Convert the embedded representative to a public key.
	rk2pk(&pkE, rkE)

	// Calculate the ephemeral shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE := xdh(skR, &pkE)

	// Calculate the static shared secret between the recipient's secret key and the sender's public
	// key.
	zzS := xdh(skR, pkS)

	// Derive the key from the shared secrets, the ephemeral public key's representative, and the
	// public keys of both the recipient and sender.
	return kdf(zzE, zzS, rkE, pkR, pkS, header)
}

// kdf returns an AES-256 key and CTR IV derived from the given ephemeral shared secret, static
// shared secret, the ephemeral public key's representative, the recipient's public key, and the
// sender's public key.
func kdf(zzE, zzS, rkE []byte, pkR, pkS *ristretto.Point, header bool) ([]byte, []byte) {
	// Concatenate the ephemeral and static shared secrets to form the initial keying material.
	ikm := append(zzE, zzS...)

	// Create a salt consisting of the ephemeral public key's representative, the recipient's public
	// key, and the sender's public key.
	salt := append(rkE, append(pkR.Bytes(), pkS.Bytes()...)...)

	// Differentiate between keys derived for encrypting headers and those for encrypting messages.
	var info []byte
	if header {
		info = []byte("header")
	} else {
		info = []byte("message")
	}

	// Create an HKDF-SHA2-512/256 instance from the initial keying material and the salt, using the
	// domain-specific info parameter to distinguish between header keys and message keys.
	h := hkdf.New(sha512.New512_256, ikm, salt, info)

	// Derive the key from the HKDF output.
	kn := make([]byte, aesKeySize+aeadIVSize)
	_, _ = io.ReadFull(h, kn)

	return kn[:aesKeySize], kn[aesKeySize:]
}

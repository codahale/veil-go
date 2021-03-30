// Package r255 provides ristretto255 functionality.
//
// Veil uses ristretto255 for asymmetric cryptography. Each person has a ristretto255/XDH key pair
// and shares their public key with each other. In place of encoded ristretto255 points, Veil
// encodes all public keys using Elligator2, making them indistinguishable from noise.
//
// To make authenticated messages, Veil creates Schnorr signatures using the signer's secret key.
// The ephemeral public key created for the signature is encoded using Elligator2, making the
// signatures indistinguishable from random noise. The actual "message" signed is a SHA-512 hash of
// the message, and SHA-512 is used to derive ristretto255 scalars from the message and ephemeral
// public key.
package r255

import (
	"crypto/rand"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
)

const (
	PublicKeySize = 32                 // PublicKeySize is the length of a public key in bytes.
	SecretKeySize = 64                 // SecretKeySize is the length of a secret key in bytes.
	SignatureSize = PublicKeySize + 32 // SignatureSize is the length of a signature in bytes.
)

// DiffieHellman performs a Diffie-Hellman key exchange using the given public key.
func DiffieHellman(sk, pk []byte) []byte {
	var (
		s ristretto.Scalar
		q ristretto.Point
	)

	// Unpack the secret key.
	s.Derive(sk)

	// Decode the public key.
	e2decode(&q, pk)

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

	// Derive the secret key.
	s.Derive(sk)

	// Calculate the public key.
	q.ScalarMultBase(&s)

	// Encode the public key with Elligator2.
	return e2encode(&q)
}

// GenerateKeys generates a key pair and returns the public key and the secret key.
func GenerateKeys() (pk, sk []byte, err error) {
	var (
		buf [SecretKeySize]byte
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

		// Convert to a secret key by hashing it with SHA-512.
		s.Derive(buf[:])

		// Encode the secret key.
		sk = buf[:]

		// Calculate the public key.
		q.ScalarMultBase(&s)

		// Encode the public key with Elligator2, if possible.
		pk = e2encode(&q)
	}

	// We generated a secret key whose public key has a representative, so return them.
	return
}

// Sign returns a Schnorr signature of the given message using the given secret key.
func Sign(sk, message []byte) ([]byte, error) {
	var (
		x, r ristretto.Scalar
		k    ristretto.Scalar
		s    ristretto.Scalar
	)

	// Generate an ephemeral key pair (R, r).
	R, skE, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	// Derive the static and ephemeral secret keys (x, r).
	x.Derive(sk)
	r.Derive(skE)

	// Derive a scalar from the ephemeral public key and the message using SHA-512 (k).
	k.Derive(append(R, message...))

	// Calculate the signature scalar (kx + r).
	s.MulAdd(&k, &x, &r)

	// Return the ephemeral public key and the signature scalar (R, s).
	return append(R, s.Bytes()...), nil
}

// Verify returns true if the given signature of the given message was created with the secret key
// corresponding to the given public key.
func Verify(pk, message, sig []byte) bool {
	var (
		y  ristretto.Point
		R  ristretto.Point
		s  ristretto.Scalar
		k  ristretto.Scalar
		Rp ristretto.Point
		ky ristretto.Point
	)

	if len(sig) != SignatureSize {
		return false
	}

	// Decode the static public key.
	e2decode(&y, pk)

	// Decode the ephemeral public key.
	e2decode(&R, sig[:PublicKeySize])

	// Unpack the signature scalar.
	_ = s.UnmarshalBinary(sig[PublicKeySize:])

	// Derive a scalar from the ephemeral public key and the message.
	k.Derive(append(sig[:PublicKeySize], message...))

	// R' = -ky + gs
	ky.ScalarMult(&y, &k)
	Rp.ScalarMultBase(&s)
	Rp.Sub(&Rp, &ky)

	// The signature is verified R and R' are equal.
	return R.Equals(&Rp)
}

// e2encode encodes the given ristretto255 point using Elligator2, returning either 32 bytes of
// uniformly-distributed data or nil, if the point is not representable with Elligator2.
func e2encode(q *ristretto.Point) []byte {
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

// e2decode decodes the given Elligator2 bytes into the given ristretto255 point.
func e2decode(q *ristretto.Point, pk []byte) {
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

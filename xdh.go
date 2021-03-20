package veil

import (
	"io"

	"github.com/bwesterb/go-ristretto"
	"github.com/bwesterb/go-ristretto/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
)

// Zero on the Ristretto255 curve.
var zero = (&ristretto.Point{}).SetZero() //nolint:gochecknoglobals // only one zero

// xdh performs a Diffie-Hellman key exchange using the given secret key and public key.
func xdh(s *ristretto.Scalar, q *ristretto.Point) []byte {
	// Multiply the point by the scalar.
	x := (&ristretto.Point{}).ScalarMult(q, s)

	// Check to see that the shared secret point is not zero. This should never happen, but it's
	// better to panic when an invariant is broken than keep chugging, and it's not hard to check.
	if x.Equals(zero) {
		panic("invalid exchange")
	}

	// Return the shared secret.
	return x.Bytes()
}

// rk2pk converts an Elligator2 representative to a public key.
func rk2pk(rk []byte, q *ristretto.Point) {
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
		// Skip those possibilities which are unrepresentable.
		if ((1 << uint(i)) & mask) == 0 {
			continue
		}

		// Convert the first representative to bytes.
		rk := fes[i].Bytes()

		// Return the public key and its representative.
		return rk[:]
	}

	// If no representative was generated, return nil.
	return nil
}

// sk2pk converts a secret key to a public key.
func sk2pk(s *ristretto.Scalar, q *ristretto.Point) {
	// Multiply the scalar by the curve base to produce the public key.
	q.ScalarMultBase(s)
}

// generateKeys generates a Ristretto255/DH key pair and returns the public key, the Elligator2
// representative of the public key, and the secret key.
func generateKeys(rand io.Reader) (q ristretto.Point, rk []byte, s ristretto.Scalar, err error) {
	var buf [64]byte

	// Not all key pairs can be represented by Elligator2, so try until we find one.
	for {
		// Generate 64 random bytes.
		if _, err = io.ReadFull(rand, buf[:]); err != nil {
			return
		}

		// Convert to a Ristretto255/DH secret key.
		s.SetReduced(&buf)

		// Generate the corresponding public key.
		sk2pk(&s, &q)

		// Calculate the public key's Elligator2 representative, if any.
		if rk = pk2rk(&q); rk == nil {
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
	_, rkE, skE, err := generateKeys(rand)
	if err != nil {
		return nil, nil, nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the ephemeral secret key and the
	// recipient's Ristretto255/DH public key.
	zzE := xdh(&skE, pkR)

	// Calculate the Ristretto255/DH shared secret between the sender's secret key and the
	// recipient's Ristretto255/DH public key.
	zzS := xdh(skS, pkR)

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
func kemReceive(skR *ristretto.Scalar, pkR, pkS *ristretto.Point, rkE, data []byte) ([]byte, []byte) {
	var pkE ristretto.Point

	// Convert the embedded Elligator2 representative to a Ristretto255/DH public key.
	rk2pk(rkE, &pkE)

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the
	// ephemeral public key.
	zzE := xdh(skR, &pkE)

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the
	// sender's public key.
	zzS := xdh(skR, pkS)

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key from the shared secret, the authenticated data, the ephemeral public key's
	// Elligator2 representative, and the public keys of both the recipient and sender.
	key, nonce := kdf(zz, data, rkE, pkR, pkS)

	return key, nonce
}

const kdfLen = chacha20poly1305.KeySize + chacha20poly1305.NonceSize

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

	// Derive the key and nonce from the HKDF output.
	kn := make([]byte, kdfLen)
	_, _ = io.ReadFull(h, kn)

	return kn[:chacha20poly1305.KeySize], kn[chacha20poly1305.KeySize:]
}

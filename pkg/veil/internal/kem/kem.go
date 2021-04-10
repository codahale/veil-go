// Package kem provides the underlying STROBE protocol for Veil's authenticated key encapsulation
// mechanism.
//
// Key encapsulation is as follows, given the sender's key pair, d_s and Q_s, the receiver's public
// key, Q_r, a plaintext message M, and tag size N:
//
//     INIT('veil.kem', level=256)
//     AD(LE_U32(N),    meta=true)
//     AD(Q_r)
//     AD(Q_s)
//     ZZ = d_sQ_r
//     KEY(ZZ)
//     SEND_ENC(M) -> C
//     SEND_MAC(N) -> T
//
// Key de-encapsulation is then the inverse of encapsulation, given the recipient's key pair, d_r
// and Q_r, and the sender's public key Q_s:
//
//     INIT('veil.kem', level=256)
//     AD(LE_U32(N),    meta=true)
//     AD(Q_r)
//     AD(Q_s)
//     ZZ = d_rQ_s
//     KEY(ZZ)
//     RECV_ENC(C) -> M
//     RECV_MAC(T)
//
// If the RECV_MAC call is successful, the plaintext message M is returned.
package kem

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dS *ristretto255.Scalar, qS, qR *ristretto255.Element, plaintext []byte, tagSize int) []byte {
	// Initialize the protocol.
	kem := internal.Strobe("veil.kem")

	// Add the tag size to the protocol.
	internal.Must(kem.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Add the recipient's public key as associated data.
	internal.Must(kem.AD(qR.Encode(nil), &strobe.Options{}))

	// Add the sender's public key as associated data.
	internal.Must(kem.AD(qS.Encode(nil), &strobe.Options{}))

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zz := ristretto255.NewElement().ScalarMult(dS, qR)

	// Key the protocol with the static shared secret.
	internal.Must(kem.KEY(zz.Encode(nil), false))

	// Copy the plaintext to a buffer.
	ciphertext := make([]byte, len(plaintext)+tagSize)
	copy(ciphertext, plaintext)

	// Encrypt the plaintext in place.
	internal.MustENC(kem.SendENC(ciphertext[:len(plaintext)], &strobe.Options{}))

	// Create a MAC.
	internal.Must(kem.SendMAC(ciphertext[len(plaintext):], &strobe.Options{}))

	// Return the the encrypted message and the MAC.
	return ciphertext
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(dR *ristretto255.Scalar, qR, qS *ristretto255.Element, ciphertext []byte, tagSize int) ([]byte, error) {
	// Initialize the protocol.
	kem := internal.Strobe("veil.kem")

	// Add the tag size to the protocol.
	internal.Must(kem.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Add the recipient's public key as associated data.
	internal.Must(kem.AD(qR.Encode(nil), &strobe.Options{}))

	// Add the sender's public key as associated data.
	internal.Must(kem.AD(qS.Encode(nil), &strobe.Options{}))

	// Calculate the shared secret between the recipient's private key and the sender's public key.
	zz := ristretto255.NewElement().ScalarMult(dR, qS)

	// Key the protocol with the shared secret.
	internal.Must(kem.KEY(zz.Encode(nil), false))

	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	// Decrypt the plaintext in place.
	internal.MustENC(kem.RecvENC(plaintext[:len(plaintext)-tagSize], &strobe.Options{}))

	// Verify the MAC.
	if err := kem.RecvMAC(plaintext[len(plaintext)-tagSize:], &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the authenticated plaintext.
	return plaintext[:len(plaintext)-tagSize], nil
}

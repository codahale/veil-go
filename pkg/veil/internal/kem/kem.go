// Package kem provides the underlying STROBE protocol for Veil's authenticated key encapsulation
// mechanism.
//
// Key encapsulation generates an ephemeral key pair, d_e and Q_e, and uses the sender's key pair,
// d_s and Q_s, and the receiver's public key, Q_r, to calculate two Diffie-Hellman shared secret
// elements, ZZ_e and ZZ_s:
//
//     ZZ_e = d_eQ_r
//     ZZ_s = d_sQ_r
//
// Key encapsulation is as follows, given a plaintext message M and tag size N:
//
//     INIT('veil.kem', level=256)
//     AD(LE_U32(N),    meta=true)
//     AD(Q_r)
//     AD(Q_s)
//     SEND_CLR(Q_e)
//     KEY(ZZ_e)
//     KEY(ZZ_s)
//     SEND_ENC(M)
//     SEND_MAC(N)
//
// The ephemeral element Q_e is sent in clear text, along ciphertext C and tag T.
//
// Key de-encapsulation re-calculates the shared secret elements, given the recipient's private key
// d_r and sender's public key Q_s:
//
//     ZZ_e = d_rQ_e
//     ZZ_s = d_rQ_s
//
// Key de-encapsulation is then the inverse of encapsulation:
//
//     INIT('veil.kem', level=256)
//     AD(LE_U32(N),    meta=true)
//     AD(Q_r)
//     AD(Q_s)
//     RECV_CLR(Q_e)
//     KEY(ZZ_e)
//     KEY(ZZ_s)
//     RECV_ENC(C)
//     RECV_MAC(T)
//
// If the RECV_MAC call is successful, the plaintext message M is returned.
//
// As a One-Pass Unified Model C(1e, 2s, ECC CDH) key agreement scheme (per NIST SP 800-56A), this
// KEM construction provides authenticity as well as confidentiality. XDH mutability issues are
// mitigated by the inclusion of the ephemeral public key and the recipient's public key in the
// inputs, and deriving the key from all data sent or received adds key-commitment with all public
// keys as openers.
//
// Unlike C(0e, 2s) schemes (e.g. NaCl's box construction), this KEM is not deterministic and will
// not reveal repeated messages. Unlike C(1e, 1s) schemes (e.g. IES), this KEM binds the sender's
// identity. This latter property is useful, as it allows for readers to confirm the sender's
// identity before beginning to decrypt the message or verify its signature. This enables the use of
// an integrated single-pass digital signature algorithm (i.e. veil.schnorr).
//
// See https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
package kem

import (
	"crypto/rand"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dS *ristretto255.Scalar, qS, qR *ristretto255.Element, plaintext []byte, tagSize int) ([]byte, error) {
	// Generate a random value.
	var buf [internal.UniformBytestringSize]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}

	// Map the random value to an ephemeral key pair.
	dE := ristretto255.NewScalar().FromUniformBytes(buf[:])
	qE := ristretto255.NewElement().ScalarBaseMult(dE)

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(dE, qR)

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dS, qR)

	// Initialize the protocol.
	kdf := internal.Strobe("veil.kem")

	// Add the tag size to the protocol.
	internal.Must(kdf.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Add the recipient's public key as associated data.
	internal.Must(kdf.AD(qR.Encode(nil), &strobe.Options{}))

	// Add the sender's public key as associated data.
	internal.Must(kdf.AD(qS.Encode(nil), &strobe.Options{}))

	// Send the ephemeral public key.
	internal.Must(kdf.SendCLR(qE.Encode(nil), &strobe.Options{}))

	// Key the protocol with the ephemeral shared secret.
	internal.Must(kdf.KEY(zzE.Encode(nil), false))

	// Key the protocol with the static shared secret.
	internal.Must(kdf.KEY(zzS.Encode(nil), false))

	// Copy the plaintext to a buffer.
	ciphertext := make([]byte, len(plaintext)+tagSize)
	copy(ciphertext, plaintext)

	// Encrypt it in place.
	internal.MustENC(kdf.SendENC(ciphertext[:len(plaintext)], &strobe.Options{}))

	// Create a MAC.
	internal.Must(kdf.SendMAC(ciphertext[len(plaintext):], &strobe.Options{}))

	// Return the ephemeral public key, the ciphertext, and the MAC.
	return append(qE.Encode(nil), ciphertext...), nil
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(dR *ristretto255.Scalar, qR, qS *ristretto255.Element, ciphertext []byte, tagSize int) ([]byte, error) {
	// Decode the ephemeral public key.
	qE := ristretto255.NewElement()
	if err := qE.Decode(ciphertext[:internal.ElementSize]); err != nil {
		return nil, err
	}

	// Calculate the ephemeral shared secret between the recipient's private key and the ephemeral
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(dR, qE)

	// Calculate the static shared secret between the recipient's private key and the sender's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dR, qS)

	// Initialize the protocol.
	kdf := internal.Strobe("veil.kem")

	// Add the tag size to the protocol.
	internal.Must(kdf.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Add the recipient's public key as associated data.
	internal.Must(kdf.AD(qR.Encode(nil), &strobe.Options{}))

	// Add the sender's public key as associated data.
	internal.Must(kdf.AD(qS.Encode(nil), &strobe.Options{}))

	// Receive the ephemeral public key.
	internal.Must(kdf.RecvCLR(ciphertext[:internal.ElementSize], &strobe.Options{}))

	// Key the protocol with the ephemeral shared secret.
	internal.Must(kdf.KEY(zzE.Encode(nil), false))

	// Key the protocol with the static shared secret.
	internal.Must(kdf.KEY(zzS.Encode(nil), false))

	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(ciphertext)-internal.ElementSize)
	copy(plaintext, ciphertext[internal.ElementSize:])

	// Decrypt it in place.
	internal.MustENC(kdf.RecvENC(plaintext[:len(plaintext)-tagSize], &strobe.Options{}))

	// Verify the MAC.
	if err := kdf.RecvMAC(plaintext[len(plaintext)-tagSize:], &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the authenticated plaintext.
	return plaintext[:len(plaintext)-tagSize], nil
}

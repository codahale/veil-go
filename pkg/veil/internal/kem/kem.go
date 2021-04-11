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
//     ZZ_s = d_sQ_r
//     KEY(ZZ_s)
//     d_e = veil.kem.nonce(d_S, M)
//     Q_e = d_eG
//     SEND_ENC(Q_e) -> E
//     SEND_MAC(N) -> T1
//     ZZ_e = d_eQ_r
//     KEY(ZZ_e)
//     SEND_ENC(M) -> C
//     SEND_MAC(N) -> T2
//
// d_e is derived as follows, given the sender's private key d_s and a message M:
//
//     INIT('veil.kem.nonce', level=256)
//     KEY(d_s)
//     AD(M)
//     PRF(64) -> d_e
//
// Key de-encapsulation is then the inverse of encapsulation, given the recipient's key pair, d_r
// and Q_r, and the sender's public key Q_s:
//
//     INIT('veil.kem', level=256)
//     AD(LE_U32(N),    meta=true)
//     AD(Q_r)
//     AD(Q_s)
//     ZZ_s = d_rQ_s
//     KEY(ZZ_s)
//     RECV_ENC(E) -> Q_e
//     RECV_MAC(T1)
//     ZZ_e = d_rQ_e
//     KEY(ZZ_e)
//     RECV_ENC(C) -> M
//     RECV_MAC(T2)
//
// If the RECV_MAC call is successful, the plaintext message M is returned.
//
// As a One-Pass Unified Model C(1e, 2s, ECC CDH) key agreement scheme (per NIST SP 800-56A), this
// KEM construction provides authenticity as well as confidentiality. XDH mutability issues are
// mitigated by the inclusion of the ephemeral public key and the recipient's public key in the
// inputs, and deriving the key from all data sent or received adds key-commitment with all public
// keys as openers.
//
// The ephemeral private key is derived from the sender's private key and the message, allowing for
// safe deterministic behavior.
//
// Unlike C(0e, 2s) schemes (e.g. NaCl's box construction), this KEM is not symmetric. Once
// encrypted, the sender cannot decrypt the ciphertext. This provides the property that the shared
// secret cannot be used to impersonate the sender in any way.
//
// Unlike C(1e, 1s) schemes (e.g. IES), this KEM binds the sender's identity. This property is
// useful, as it allows for readers to confirm the sender's identity before beginning to decrypt the
// message or verify its signature. This enables the use of an integrated single-pass digital
// signature algorithm (i.e. veil.schnorr). It also means the ciphertext is not decryptable without
// knowledge of the sender's public key.
//
// In addition, this KEM does not require the transmission of ristretto255 elements in cleartext. A
// passive adversary scanning for encoded elements would first need the parties' static
// Diffie-Hellman secret.
//
// See https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
package kem

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dS *ristretto255.Scalar, qS, qR *ristretto255.Element, plaintext []byte) []byte {
	const (
		macStart = internal.ElementSize
		macEnd   = macStart + internal.TagSize
	)

	// Initialize the protocol.
	kem := internal.Strobe("veil.kem")

	// Add the tag size to the protocol.
	internal.Must(kem.AD(internal.LittleEndianU32(internal.TagSize), &strobe.Options{Meta: true}))

	// Add the recipient's public key as associated data.
	internal.Must(kem.AD(qR.Encode(nil), &strobe.Options{}))

	// Add the sender's public key as associated data.
	internal.Must(kem.AD(qS.Encode(nil), &strobe.Options{}))

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dS, qR)

	// Key the protocol with the static shared secret.
	internal.Must(kem.KEY(zzS.Encode(nil), false))

	// Deterministically derive an ephemeral private key from the sender's private key and the
	// message.
	dE := deriveEphemeral(dS, plaintext)
	qE := ristretto255.NewElement().ScalarBaseMult(dE)

	// Copy the ephemeral public key to a buffer.
	ciphertext := make([]byte, macStart+len(plaintext)+(2*internal.TagSize))
	qE.Encode(ciphertext[:0])

	// Encrypt the ephemeral public key in place..
	internal.MustENC(kem.SendENC(ciphertext[:macStart], &strobe.Options{}))

	// Send a MAC.
	internal.Must(kem.SendMAC(ciphertext[macStart:macEnd], &strobe.Options{}))

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(dE, qR)

	// Key the protocol with the ephemeral shared secret.
	internal.Must(kem.KEY(zzE.Encode(nil), false))

	// Copy the plaintext to the buffer.
	copy(ciphertext[macEnd:], plaintext)

	// Encrypt the plaintext in place.
	internal.MustENC(kem.SendENC(ciphertext[macEnd:macEnd+len(plaintext)],
		&strobe.Options{}))

	// Create a MAC.
	internal.Must(kem.SendMAC(ciphertext[macEnd+len(plaintext):], &strobe.Options{}))

	// Return the encrypted ephemeral public key, the encrypted message, and the MAC.
	return ciphertext
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(dR *ristretto255.Scalar, qR, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	// Copy the ciphertext to a buffer.
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	// Initialize the protocol.
	kem := internal.Strobe("veil.kem")

	// Add the tag size to the protocol.
	internal.Must(kem.AD(internal.LittleEndianU32(internal.TagSize), &strobe.Options{Meta: true}))

	// Add the recipient's public key as associated data.
	internal.Must(kem.AD(qR.Encode(nil), &strobe.Options{}))

	// Add the sender's public key as associated data.
	internal.Must(kem.AD(qS.Encode(nil), &strobe.Options{}))

	// Calculate the static shared secret between the recipient's private key and the sender's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dR, qS)

	// Key the protocol with the static shared secret.
	internal.Must(kem.KEY(zzS.Encode(nil), false))

	// Decrypt the ephemeral public key.
	internal.MustENC(kem.RecvENC(plaintext[:internal.ElementSize], &strobe.Options{}))

	// Check the MAC.
	if err := kem.RecvMAC(
		plaintext[internal.ElementSize:internal.ElementSize+internal.TagSize],
		&strobe.Options{},
	); err != nil {
		return nil, err
	}

	// Decode the ephemeral public key.
	qE := ristretto255.NewElement()
	if err := qE.Decode(plaintext[:internal.ElementSize]); err != nil {
		return nil, err
	}

	plaintext = plaintext[internal.ElementSize+internal.TagSize:]

	// Calculate the ephemeral shared secret between the recipient's private key and the ephemeral
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(dR, qE)

	// Key the protocol with the ephemeral shared secret.
	internal.Must(kem.KEY(zzE.Encode(nil), false))

	// Decrypt it in place.
	internal.MustENC(kem.RecvENC(plaintext[:len(plaintext)-internal.TagSize], &strobe.Options{}))

	// Verify the MAC.
	if err := kem.RecvMAC(plaintext[len(plaintext)-internal.TagSize:], &strobe.Options{}); err != nil {
		return nil, err
	}

	// Return the authenticated plaintext.
	return plaintext[:len(plaintext)-internal.TagSize], nil
}

// deriveEphemeral derives an ephemeral scalar from a KEM sender's private key and a message.
func deriveEphemeral(d *ristretto255.Scalar, msg []byte) *ristretto255.Scalar {
	var buf [internal.UniformBytestringSize]byte

	// Initialize the protocol.
	kemNonce := internal.Strobe("veil.kem.nonce")

	// Key the protocol with the sender's private key.
	internal.Must(kemNonce.KEY(d.Encode(nil), false))

	// Include the message as associated data.
	internal.Must(kemNonce.AD(msg, &strobe.Options{}))

	// Generate 64 bytes of PRF output.
	internal.Must(kemNonce.PRF(buf[:], false))

	// Map the PRF output to a scalar.
	return ristretto255.NewScalar().FromUniformBytes(buf[:])
}

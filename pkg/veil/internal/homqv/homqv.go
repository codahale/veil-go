// Package homqv implements HOMQV (aka Hashed One-Pass MQV) as a secure signcryption KEM/DEM, with
// the ephemeral element being encrypted with the static ECDH shared secret before transmission.
//
//     We thus conclude that when used in conjunction with PKI, the protocol HOMQV with the DEM part
//     can UC-realize secure messaging. This UC-secure-messaging, in turn, can be used to transport
//     keys from server to client, providing as much security as can be obtained from a one-pass
//     protocol.
//
// This retains the properties of HOMQV with the advantage of being indistinguishable from random
// noise.
//
// Encryption is as follows, given the sender's key pair, d_s and Q_s, the receiver's public key,
// Q_r, a plaintext message M, and tag size N:
//
//     INIT('veil.homqv', level=256)
//     AD(LE_U32(N),      meta=true)
//     ZZ = d_sQ_r
//     KEY(ZZ)
//     AD(Q_r)
//     AD(Q_s)
//
// The protocol's state is then cloned, and an ephemeral scalar is derived from the sender's private
// key and the message:
//
//     KEY(d_s)
//     AD(M)
//     PRF(64) -> d_e
//
// The cloned protocol's state is discarded and the scalar returned to the parent protocol, where an
// ephemeral key pair is created:
//
//     Q_e = d_eG
//
// The ephemeral public element is encrypted and transmitted:
//
//     SEND_ENC(Q_e) -> E
//
// The HOMQV shared secret is calculated and used as a key:
//
//     PRF(64) -> e
//     σ = Q_r(ed_s + d_e)
//     KEY(σ)
//
// Finally, the plaintext message is encrypted and sent along with a MAC:
//
//     SEND_ENC(M) -> C
//     SEND_MAC(N) -> T
//
// Decryption is the inverse of encryption, given the recipient's private key, d_r:
//
//     INIT('veil.homqv', level=256)
//     AD(LE_U32(N),      meta=true)
//     ZZ = d_rQ_s
//     KEY(ZZ)
//     AD(Q_r)
//     AD(Q_s)
//     RECV_ENC(E) -> Q_e
//     PRF(64) -> e
//     σ = d_r(eQ_s + Q_e)
//     KEY(σ)
//     RECV_ENC(C) -> M
//     RECV_MAC(T)
//
// If the RECV_MAC call is successful, the plaintext message M is returned.
//
// See https://link.springer.com/content/pdf/10.1007/978-3-642-19379-8_20.pdf
package homqv

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/gtank/ristretto255"
)

// Overhead is the number of bytes HOMQV adds to ciphertexts.
const Overhead = internal.ElementSize + internal.TagSize

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dst []byte, dS *ristretto255.Scalar, qS, qR *ristretto255.Element, plaintext []byte) []byte {
	var buf [internal.ElementSize]byte

	// Allocate output buffer.
	ret, out := internal.SliceForAppend(dst, internal.ElementSize+len(plaintext)+internal.TagSize)

	// Initialize protocol.
	homqv := protocol.New("veil.homqv")
	homqv.AD(protocol.LittleEndianU32(internal.TagSize))

	// Key protocol with static shared secret.
	homqv.KEY(ristretto255.NewElement().ScalarMult(dS, qR).Encode(buf[:0]))

	// Include sender and recipient's public keys as associated data.
	homqv.AD(qS.Encode(buf[:0]))
	homqv.AD(qR.Encode(buf[:0]))

	// Clone the protocol's context and key with the sender's private key and plaintext.
	clone := homqv.Clone()
	clone.KEY(dS.Encode(buf[:0]))
	clone.AD(plaintext)

	// Derive an ephemeral key pair from the cloned context.
	dE := clone.PRFScalar()
	qE := ristretto255.NewElement().ScalarBaseMult(dE)

	// Encrypt and send the ephemeral element.
	out = homqv.SendENC(out[:0], qE.Encode(buf[:0]))

	// Extract a challenge scalar.
	e := homqv.PRFScalar()

	// Calculate the shared secret.
	sigma := ristretto255.NewElement().ScalarMult(
		ristretto255.NewScalar().Add(ristretto255.NewScalar().Multiply(dS, e), dE), qR)

	// Key with the shared secret.
	homqv.KEY(sigma.Encode(buf[:0]))

	// Encrypt the plaintext.
	out = homqv.SendENC(out, plaintext)

	// Send a MAC of everything.
	_ = homqv.SendMAC(out, internal.TagSize)

	return ret
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(dst []byte, dR *ristretto255.Scalar, qR, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	var buf [internal.ElementSize]byte

	// Initialize the protocol.
	homqv := protocol.New("veil.homqv")
	homqv.AD(protocol.LittleEndianU32(internal.TagSize))

	// Key with the static shared secret.
	homqv.KEY(ristretto255.NewElement().ScalarMult(dR, qS).Encode(buf[:0]))

	// Include sender and recipient's public keys as associated data.
	homqv.AD(qS.Encode(buf[:0]))
	homqv.AD(qR.Encode(buf[:0]))

	// Decrypt and decode the ephemeral public key.
	qE := ristretto255.NewElement()
	if err := qE.Decode(homqv.RecvENC(buf[:0], ciphertext[:internal.ElementSize])); err != nil {
		return nil, err
	}

	// Extract a challenge scalar.
	e := homqv.PRFScalar()

	// Re-calculate the shared secret.
	sigma := ristretto255.NewElement().ScalarMult(dR,
		ristretto255.NewElement().Add(ristretto255.NewElement().ScalarMult(e, qS), qE))

	// Key with the shared secret.
	homqv.KEY(sigma.Encode(buf[:0]))

	// Decrypt the plaintext.
	plaintext := homqv.RecvENC(dst, ciphertext[internal.ElementSize:len(ciphertext)-internal.TagSize])

	// Verify the MAC.
	if err := homqv.RecvMAC(ciphertext[len(ciphertext)-internal.TagSize:]); err != nil {
		return nil, err
	}

	// If the MAC verifies, return the plaintext.
	return plaintext, nil
}

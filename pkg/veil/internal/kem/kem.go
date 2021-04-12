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
//     ZZ_e = d_eQ_r
//     KEY(ZZ_e)
//     SEND_ENC(M) -> C
//     SEND_MAC(N) -> T
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
//     ZZ_e = d_rQ_e
//     KEY(ZZ_e)
//     RECV_ENC(C) -> M
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
// The ephemeral private key is derived from the sender's private key and the message, allowing for
// safe deterministic behavior.
//
// Unlike C(0e, 2s) schemes (e.g. NaCl's box construction), this KEM provides forward security for
// the sender. If the sender's private key is compromised, the most an attacker can discover about
// previously sent messages is the ephemeral public key, not the message itself.
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
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/gtank/ristretto255"
)

const Overhead = internal.ElementSize + internal.TagSize

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dst []byte, dS *ristretto255.Scalar, qS, qR *ristretto255.Element, plaintext []byte) []byte {
	ret, out := internal.SliceForAppend(dst, len(plaintext)+Overhead)

	// Initialize the protocol.
	kem := protocol.New("veil.kem")

	// Add the tag size to the protocol.
	kem.MetaAD(protocol.LittleEndianU32(internal.TagSize))

	// Add the recipient's public key as associated data.
	kem.AD(qR.Encode(nil))

	// Add the sender's public key as associated data.
	kem.AD(qS.Encode(nil))

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dS, qR)

	// Key the protocol with the static shared secret.
	kem.KEY(zzS.Encode(nil))

	// Deterministically derive an ephemeral private key from the sender's private key and the
	// message.
	dE := deriveEphemeral(dS, plaintext)
	qE := ristretto255.NewElement().ScalarBaseMult(dE)

	// Encrypt the ephemeral public key.
	out = kem.SendENC(out[:0], qE.Encode(nil))

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(dE, qR)

	// Key the protocol with the ephemeral shared secret.
	kem.KEY(zzE.Encode(nil))

	// Encrypt the plaintext.
	out = kem.SendENC(out, plaintext)

	// Create a MAC.
	_ = kem.SendMAC(out, internal.TagSize)

	// Return the encrypted ephemeral public key, the encrypted message, and the MAC.
	return ret
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(dst []byte, dR *ristretto255.Scalar, qR, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	// Initialize the protocol.
	kem := protocol.New("veil.kem")

	// Add the tag size to the protocol.
	kem.MetaAD(protocol.LittleEndianU32(internal.TagSize))

	// Add the recipient's public key as associated data.
	kem.AD(qR.Encode(nil))

	// Add the sender's public key as associated data.
	kem.AD(qS.Encode(nil))

	// Calculate the static shared secret between the recipient's private key and the sender's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dR, qS)

	// Key the protocol with the static shared secret.
	kem.KEY(zzS.Encode(nil))

	// Decrypt the ephemeral public key.
	qEb := kem.RecvENC(nil, ciphertext[:internal.ElementSize])

	ciphertext = ciphertext[internal.ElementSize:]

	// Decode the ephemeral public key. N.B.: this value has only been decrypted and not
	// authenticated.
	qE := ristretto255.NewElement()
	if err := qE.Decode(qEb); err != nil {
		return nil, err
	}

	// Calculate the ephemeral shared secret between the recipient's private key and the ephemeral
	// public key. N.B.: this value is derived from the unauthenticated ephemeral public key.
	zzE := ristretto255.NewElement().ScalarMult(dR, qE)

	// Key the protocol with the ephemeral shared secret.
	kem.KEY(zzE.Encode(nil))

	// Decrypt the plaintext. N.B.: This has not been authenticated yet.
	plaintext := kem.RecvENC(dst, ciphertext[:len(ciphertext)-internal.TagSize])

	// Verify the MAC. This establishes authentication for the previous operations in their
	// entirety, since the sender and receiver's protocol states must be identical in order for the
	// MACs to agree.
	if err := kem.RecvMAC(ciphertext[len(ciphertext)-internal.TagSize:]); err != nil {
		return nil, err
	}

	// Return the authenticated plaintext.
	return plaintext, nil
}

// deriveEphemeral derives an ephemeral scalar from a KEM sender's private key and a message.
func deriveEphemeral(d *ristretto255.Scalar, msg []byte) *ristretto255.Scalar {
	// Initialize the protocol.
	kemNonce := protocol.New("veil.kem.nonce")

	// Key the protocol with the sender's private key.
	kemNonce.KEY(d.Encode(nil))

	// Include the message as associated data.
	kemNonce.AD(msg)

	// Generate 64 bytes of PRF output and map it to a scalar.
	return kemNonce.PRFScalar()
}

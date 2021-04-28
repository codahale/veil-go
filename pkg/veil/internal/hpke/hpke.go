// Package hpke provides the underlying STROBE protocol for Veil's authenticated hybrid public key
// encryption system. Unlike traditional HPKE constructions, this does not have separate KEM/DEM
// components or a specific derived DEK.
//
// Encryption
//
// Encryption is as follows, given the sender's key pair, d_s and Q_s, an ephemeral key pair, d_e
// and Q_e, the receiver's public key, Q_r, a plaintext message P, and MAC size N_mac:
//
//  INIT('veil.hpke', level=256)
//  AD(LE_U32(N_mac), meta=true)
//  AD(Q_r)
//  AD(Q_s)
//  ZZ_s = Q_r^d_s
//  KEY(ZZ_s)
//  SEND_ENC(Q_e) -> E
//  ZZ_e = Q_r^d_e
//  KEY(ZZ_e)
//
// This is effectively an authenticated ECDH KEM, but instead of returning KDF output for use in a
// DEM, we use the keyed protocol to directly encrypt the ciphertext and create a MAC:
//
//  SEND_ENC(P)     -> C
//  SEND_MAC(N_mac) -> M
//
// The resulting ciphertext is the concatenation of E, C, and M.
//
// Decryption
//
// Decryption is then the inverse of encryption, given the recipient's key pair, d_r and Q_r, and
// the sender's public key Q_s:
//
//  INIT('veil.hpke', level=256)
//  AD(LE_U32(N_max), meta=true)
//  AD(Q_r)
//  AD(Q_s)
//  ZZ_s = Q_s^d_r
//  KEY(ZZ_s)
//  RECV_ENC(E) -> Q_e
//  ZZ_e = Q_e^d_r
//  KEY(ZZ_e)
//  RECV_ENC(C) -> P
//  RECV_MAC(M)
//
// If the RECV_MAC call is successful, the ephemeral public key E and the plaintext message P are
// returned.
//
// IND-CCA2 Security
//
// This construction combines two overlapping KEM/DEM constructions: a "El Gamal-like" KEM combined
// with a STROBE-based AEAD, and an ephemeral ECIES-style KEM combined with a STROBE-based AEAD.
//
// The STROBE-based AEAD is equivalent to Construction 5.6 of Modern Cryptography 3e and is
// CCA-secure per Theorem 5.7, provided STROBE's encryption is CPA-secure. STROBE's SEND_ENC is
// equivalent to Construction 3.31 and is CPA-secure per Theorem 3.29, provided STROBE is a
// sufficiently strong pseudorandom function.
//
// The first KEM/DEM construction is equivalent to Construction 12.19 of Modern Cryptography 3e, and
// is CCA-secure per Theorem 12.22, provided the gap-CDH problem is hard relative to ristretto255
// and STROBE is modeled as a random oracle.
//
// The second KEM/DEM construction is equivalent to Construction 12.23 of Modern Cryptography 3e,
// and is CCA-secure per Corollary 12.24, again provided that the gap-CDH problem is hard relative
// to ristretto255 and STROBE is modeled as a random oracle.
//
// IK-CCA Security
//
// veil.hpke is IK-CCA (per Bellare, https://iacr.org/archive/asiacrypt2001/22480568.pdf), in that
// it is impossible for an attacker in possession of two public keys to determine which of the two
// keys a given ciphertext was encrypted with in either chosen-plaintext or chosen-ciphertext
// attacks. Informally, veil.hpke ciphertexts consist exclusively of STROBE ciphertext and PRF
// output; an attacker being able to distinguish between ciphertexts based on keying material would
// imply STROBE's AEAD construction is not IND-CCA2.
//
// Consequently, a passive adversary scanning for encoded elements would first need the parties'
// static Diffie-Hellman secret in order to distinguish messages from random noise.
//
// Forward Sender Security
//
// Because the ephemeral private key is discarded after encryption, a compromise of the sender's
// private key will not compromise previously-created ciphertexts. If the sender's private key is
// compromised, the most an attacker can discover about previously sent messages is the ephemeral
// public key, not the message itself.
//
// Insider Authenticity
//
// This construction is not secure against insider attacks on authenticity, nor is it intended to
// be. A recipient can forge ciphertexts which appear to be from a sender by re-using the ephemeral
// public key and encrypting an alternate plaintext, but the forgeries will only be decryptable by
// the forger. Because this type of forgery is possible, veil.hpke ciphertexts are therefore
// repudiable.
//
// Randomness Re-Use
//
// The ephemeral key pair, d_e and Q_e, are generated outside of this construction and can be used
// multiple times for a single message.
// This improves the efficiency of the scheme without reducing
// its security, per Bellare et al.'s treatment of Randomness Reusing Multi-Recipient Encryption
// Schemes (http://cseweb.ucsd.edu/~Mihir/papers/bbs.pdf).
//
package hpke

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/gtank/ristretto255"
)

// Overhead is the number of bytes added to each veil.hpke ciphertext.
const Overhead = internal.ElementSize + internal.MACSize

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dst []byte, dS, dE *ristretto255.Scalar, qS, qE, qR *ristretto255.Element, plaintext []byte) []byte {
	buf := make([]byte, internal.ElementSize)
	ret, out := internal.SliceForAppend(dst, len(plaintext)+Overhead)

	// Initialize the protocol.
	hpke := protocol.New("veil.hpke")

	// Add the MAC size to the protocol.
	hpke.MetaAD(protocol.LittleEndianU32(internal.MACSize))

	// Add the recipient's public key as associated data.
	hpke.AD(qR.Encode(buf[:0]))

	// Add the sender's public key as associated data.
	hpke.AD(qS.Encode(buf[:0]))

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dS, qR)

	// Key the protocol with the static shared secret.
	hpke.KEY(zzS.Encode(buf[:0]))

	// Encrypt the ephemeral public key.
	out = hpke.SendENC(out[:0], qE.Encode(buf[:0]))

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(dE, qR)

	// Key the protocol with the ephemeral shared secret.
	hpke.KEY(zzE.Encode(buf[:0]))

	// Encrypt the plaintext.
	out = hpke.SendENC(out, plaintext)

	// Create a MAC.
	_ = hpke.SendMAC(out)

	// Return the encrypted ephemeral public key, the encrypted message, and the MAC.
	return ret
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(
	dst []byte, dR *ristretto255.Scalar, qR, qS *ristretto255.Element, ciphertext []byte,
) (*ristretto255.Element, []byte, error) {
	buf := make([]byte, internal.ElementSize)
	ret, out := internal.SliceForAppend(dst, len(ciphertext)-Overhead)

	// Initialize the protocol.
	hpke := protocol.New("veil.hpke")

	// Add the MAC size to the protocol.
	hpke.MetaAD(protocol.LittleEndianU32(internal.MACSize))

	// Add the recipient's public key as associated data.
	hpke.AD(qR.Encode(buf[:0]))

	// Add the sender's public key as associated data.
	hpke.AD(qS.Encode(buf[:0]))

	// Calculate the static shared secret between the recipient's private key and the sender's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dR, qS)

	// Key the protocol with the static shared secret.
	hpke.KEY(zzS.Encode(buf[:0]))

	// Decrypt and decode the ephemeral public key. N.B.: this value has only been decrypted and not
	// authenticated.
	qE := ristretto255.NewElement()
	if err := qE.Decode(hpke.RecvENC(buf[:0], ciphertext[:internal.ElementSize])); err != nil {
		return nil, nil, internal.ErrInvalidCiphertext
	}

	// Calculate the ephemeral shared secret between the recipient's private key and the ephemeral
	// public key. N.B.: this value is derived from the unauthenticated ephemeral public key.
	zzE := ristretto255.NewElement().ScalarMult(dR, qE)

	// Key the protocol with the ephemeral shared secret.
	hpke.KEY(zzE.Encode(buf[:0]))

	ciphertext = ciphertext[internal.ElementSize:]

	// Decrypt the plaintext. N.B.: this value has only been decrypted and not authenticated.
	hpke.RecvENC(out[:0], ciphertext[:len(ciphertext)-internal.MACSize])

	// Verify the MAC. This establishes authentication for the previous operations in their
	// entirety, since the sender and receiver's protocol states must be identical in order for the
	// MACs to agree.
	if err := hpke.RecvMAC(ciphertext[len(ciphertext)-internal.MACSize:]); err != nil {
		return nil, nil, internal.ErrInvalidCiphertext
	}

	// Return the ephemeral public key and the authenticated plaintext.
	return qE, ret, nil
}

// Package atkem provides the underlying STROBE protocol for Veil's authenticated, tagged key
// encapsulation mechanism. It integrates an atKEM construction with an AEAD for wrapping arbitrary
// data.
//
// Encryption
//
// Encryption is as follows, given the sender's key pair, d_s and Q_s, the receiver's public key,
// Q_r, a tag T, a plaintext message P, and MAC size N_mac:
//
//  INIT('veil.atkem', level=256)
//  AD(LE_U32(N_mac),  meta=true)
//  AD(Q_r)
//  AD(Q_s)
//  KEY(T)
//  ZZ_s = Q_r^d_s
//  KEY(ZZ_s)
//
// The protocol's state is then cloned, the clone is keyed with 64 bytes of random data, the
// sender's private key, and the message, and finally an ephemeral scalar is derived from PRF output:
//
//  KEY(rand(64))
//  KEY(d_s)
//  KEY(P)
//  PRF(64) -> d_e
//
// The clone's state is discarded, and d_e is returned to the parent:
//
//  Q_e = G^d_e
//  SEND_ENC(Q_e) -> E
//  ZZ_e = Q_r^d_e
//  KEY(ZZ_e)
//
// This is effectively an authenticated ECDH KEM, but instead of returning PRF output for use in a
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
//  INIT('veil.atkem', level=256)
//  AD(LE_U32(N_max),  meta=true)
//  AD(Q_r)
//  AD(Q_s)
//  KEY(T)
//  ZZ_s = Q_s^d_r
//  KEY(ZZ_s)
//  RECV_ENC(E) -> Q_e
//  ZZ_e = Q_e^d_r
//  KEY(ZZ_e)
//  RECV_ENC(C) -> P
//  RECV_MAC(M)
//
// If the RECV_MAC call is successful, the plaintext message P is returned.
//
// IND-CCA2 Security
//
// This construction combines two overlapping KEM/DEM constructions: a "El Gamal-like" KEM combined
// with a STROBE-based AEAD, and an ephemeral ECIES-style KEM combined with a STROBE-based AEAD,
// both extended with the Tag-KEM construction from Abe et al.
// (https://www.shoup.net/papers/tagkemdem.pdf).
//
// The STROBE-based AEAD is equivalent to Construction 5.6 of Modern Cryptography 3e and is
// CCA-secure per Theorem 5.7, provided STROBE's encryption is CPA-secure. STROBE's SEND_ENC is
// equivalent to Construction 3.31 and is CPA-secure per Theorem 3.29, provided STROBE is a
// sufficiently strong pseudorandom function.
//
// With a fixed tag, the first KEM/DEM construction is equivalent to Construction 12.19 of Modern
// Cryptography 3e, and is CCA-secure per Theorem 12.22, provided the gap-CDH problem is hard
// relative to ristretto255 and STROBE is modeled as a random oracle. The addition of a tag does not
// compromise the construction CCA-security, per Abe et al.
//
// With a fixed tag, the second KEM/DEM construction is equivalent to Construction 12.23 of Modern
// Cryptography 3e, and is CCA-secure per Corollary 12.24, again provided that the gap-CDH problem
// is hard relative to ristretto255 and STROBE is modeled as a random oracle. The addition of a tag
// does not compromise the construction CCA-security, per Abe et al.
//
// IK-CCA Security
//
// veil.atkem is IK-CCA (per Bellare, https://iacr.org/archive/asiacrypt2001/22480568.pdf), in that
// it is impossible for an attacker in possession of two public keys to determine which of the two
// keys a given ciphertext was encrypted with in either chosen-plaintext or chosen-ciphertext
// attacks. Informally, veil.atkem ciphertexts consist exclusively of STROBE ciphertext and PRF
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
// the forger. Because this type of forgery is possible, veil.atkem ciphertexts are therefore
// repudiable.
//
// Ephemeral Key Hedging
//
// In deriving the ephemeral scalar from a cloned context, veil.atkem uses Aranha et al.'s hedging
// technique (https://eprint.iacr.org/2019/956.pdf) to mitigate against both catastrophic randomness
// failures and differential fault attacks against purely deterministic PKE schemes.
package atkem

import (
	"crypto/rand"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/gtank/ristretto255"
)

// Overhead is the number of bytes added to each veil.atkem ciphertext.
const Overhead = internal.ElementSize + internal.MACSize

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dst []byte, dS *ristretto255.Scalar, qS, qR *ristretto255.Element, tag, plaintext []byte) ([]byte, error) {
	var buf [internal.UniformBytestringSize]byte

	ret, out := internal.SliceForAppend(dst, len(plaintext)+Overhead)

	// Initialize the protocol.
	atkem := protocol.New("veil.atkem")

	// Add the MAC size to the protocol.
	atkem.MetaAD(protocol.LittleEndianU32(internal.MACSize))

	// Add the recipient's public key as associated data.
	atkem.AD(qR.Encode(buf[:0]))

	// Add the sender's public key as associated data.
	atkem.AD(qS.Encode(buf[:0]))

	// Key the protocol with the tag.
	atkem.KEY(tag)

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dS, qR)

	// Key the protocol with the static shared secret.
	atkem.KEY(zzS.Encode(buf[:0]))

	// Clone the protocol.
	clone := atkem.Clone()

	// Generate a random nonce.
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}

	// Key the clone with the nonce. This hedges against differential attacks against purely
	// deterministic PKE algorithms.
	clone.KEY(buf[:internal.UniformBytestringSize])

	// Key the clone with the sender's private key. This hedges against randomness failures.
	clone.KEY(dS.Encode(buf[:0]))

	// Key the clone with the plaintext. This hedges against the reuse of ephemeral values across
	// multiple messages.
	clone.KEY(plaintext)

	// Derive an ephemeral key pair from the clone.
	dE := clone.PRFScalar()
	qE := ristretto255.NewElement().ScalarBaseMult(dE)

	// Encrypt the ephemeral public key.
	out = atkem.SendENC(out[:0], qE.Encode(buf[:0]))

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(dE, qR)

	// Key the protocol with the ephemeral shared secret.
	atkem.KEY(zzE.Encode(buf[:0]))

	// Encrypt the plaintext.
	out = atkem.SendENC(out, plaintext)

	// Create a MAC.
	_ = atkem.SendMAC(out)

	// Return the encrypted ephemeral public key, the encrypted message, and the MAC.
	return ret, nil
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(
	dst []byte, dR *ristretto255.Scalar, qR, qS *ristretto255.Element, tag, ciphertext []byte,
) ([]byte, error) {
	var buf [internal.ElementSize]byte

	// Initialize the protocol.
	atkem := protocol.New("veil.atkem")

	// Add the MAC size to the protocol.
	atkem.MetaAD(protocol.LittleEndianU32(internal.MACSize))

	// Add the recipient's public key as associated data.
	atkem.AD(qR.Encode(buf[:0]))

	// Add the sender's public key as associated data.
	atkem.AD(qS.Encode(buf[:0]))

	// Key the protocol with the tag.
	atkem.KEY(tag)

	// Calculate the static shared secret between the recipient's private key and the sender's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dR, qS)

	// Key the protocol with the static shared secret.
	atkem.KEY(zzS.Encode(buf[:0]))

	// Decrypt and decode the ephemeral public key. N.B.: this value has only been decrypted and not
	// authenticated.
	qE := ristretto255.NewElement()
	if err := qE.Decode(atkem.RecvENC(buf[:0], ciphertext[:internal.ElementSize])); err != nil {
		return nil, internal.ErrInvalidCiphertext
	}

	// Calculate the ephemeral shared secret between the recipient's private key and the ephemeral
	// public key. N.B.: this value is derived from the unauthenticated ephemeral public key.
	zzE := ristretto255.NewElement().ScalarMult(dR, qE)

	// Key the protocol with the ephemeral shared secret.
	atkem.KEY(zzE.Encode(buf[:0]))

	// Trim and allocate buffers.
	ret, out := internal.SliceForAppend(dst, len(ciphertext)-Overhead)
	ciphertext = ciphertext[internal.ElementSize:]

	// Decrypt the plaintext. N.B.: this value has only been decrypted and not authenticated.
	atkem.RecvENC(out[:0], ciphertext[:len(ciphertext)-internal.MACSize])

	// Verify the MAC. This establishes authentication for the previous operations in their
	// entirety, since the sender and receiver's protocol states must be identical in order for the
	// MACs to agree.
	if err := atkem.RecvMAC(ciphertext[len(ciphertext)-internal.MACSize:]); err != nil {
		return nil, internal.ErrInvalidCiphertext
	}

	// Return the authenticated plaintext.
	return ret, nil
}

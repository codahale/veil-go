// Package hpke provides the underlying STROBE protocol for Veil's authenticated hybrid public key
// encryption system. Unlike traditional HPKE constructions, this does not have separate KEM/DEM
// components or a specific derived DEK.
//
// Encryption
//
// Encryption is as follows, given the sender's key pair, d_s and Q_s, the receiver's public key,
// Q_r, a plaintext message M, and tag size N:
//
//     INIT('veil.hpke', level=256)
//     AD(LE_U32(N),     meta=true)
//     AD(Q_r)
//     AD(Q_s)
//     ZZ_s = d_sQ_r
//     KEY(ZZ_s)
//
// The protocol's state is then cloned, the clone is keyed with 64 bytes of random data, the
// sender's private key, and the message, and finally an ephemeral scalar is derived from PRF output:
//
//     KEY(rand(64))
//     KEY(d_s)
//     KEY(M)
//     PRF(64) -> d_e
//
// The clone's state is discarded, and d_e is returned to the parent:
//
//     Q_e = d_eG
//     SEND_ENC(Q_e) -> E
//     ZZ_e = d_eQ_r
//     KEY(ZZ_e)
//
// This is effectively an authenticated ECDH KEM, but instead of returning PRF output for use in a
// DEM, we use the keyed protocol to directly encrypt the ciphertext and create an authentication
// tag:
//
//     SEND_ENC(M) -> C
//     SEND_MAC(N) -> T
//
// Decryption
//
// Decryption is then the inverse of encryption, given the recipient's key pair, d_r and Q_r, and
// the sender's public key Q_s:
//
//     INIT('veil.hpke', level=256)
//     AD(LE_U32(N),     meta=true)
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
// IND-CCA2 Security
//
// This construction is, essentially, the AuthEncap construction from HPKE
// (https://tools.ietf.org/html/draft-irtf-cfrg-hpke-08#section-4.1), with the ephemeral public key
// being encrypted with the static shared key, and the plaintext encrypted with both ephemeral and
// static shared keys via AEAD. Consequently, the analysis by Alwen et al.
// (https://eprint.iacr.org/2020/1499.pdf) and Lipp (https://eprint.iacr.org/2020/243.pdf) indicates
// this construction provides IND-CCA2 security in the multi-user setting. Unlike HPKE, however, a
// passive adversary scanning for encoded elements would first need the parties' static
// Diffie-Hellman secret in order to distinguish messages from random noise.
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
// Ephemeral Key Hedging
//
// In deriving the ephemeral scalar from a cloned context, veil.hpke uses Aranha et al.'s hedging
// technique (https://eprint.iacr.org/2019/956.pdf) to mitigate against both catastrophic randomness
// failures and differential fault attacks against purely deterministic PKE schemes.
package hpke

import (
	"crypto/rand"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/gtank/ristretto255"
)

// Overhead is the number of bytes added to each veil.hpke ciphertext.
const Overhead = internal.ElementSize + internal.TagSize

// Encrypt encrypts the plaintext such that the owner of qR will be able to decrypt it knowing that
// only the owner of qS could have encrypted it.
func Encrypt(dst []byte, dS *ristretto255.Scalar, qS, qR *ristretto255.Element, plaintext []byte) ([]byte, error) {
	var buf [internal.UniformBytestringSize]byte

	ret, out := internal.SliceForAppend(dst, len(plaintext)+Overhead)

	// Initialize the protocol.
	hpke := protocol.New("veil.hpke")

	// Add the tag size to the protocol.
	hpke.MetaAD(protocol.LittleEndianU32(internal.TagSize))

	// Add the recipient's public key as associated data.
	hpke.AD(qR.Encode(buf[:0]))

	// Add the sender's public key as associated data.
	hpke.AD(qS.Encode(buf[:0]))

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(dS, qR)

	// Key the protocol with the static shared secret.
	hpke.KEY(zzS.Encode(buf[:0]))

	// Clone the protocol.
	clone := hpke.Clone()

	// Generate a random nonce.
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}

	// Key the clone with the nonce.
	clone.KEY(buf[:internal.UniformBytestringSize])

	// Key the clone with the sender's private key.
	clone.KEY(dS.Encode(buf[:0]))

	// Key the clone with the message.
	clone.KEY(plaintext)

	// Derive an ephemeral key pair from the clone.
	dE := clone.PRFScalar()
	qE := ristretto255.NewElement().ScalarBaseMult(dE)

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
	return ret, nil
}

// Decrypt decrypts the ciphertext iff it was encrypted by the owner of qS for the owner of qR and
// no bit of the ciphertext has been modified.
func Decrypt(dst []byte, dR *ristretto255.Scalar, qR, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	var buf [internal.ElementSize]byte

	// Initialize the protocol.
	hpke := protocol.New("veil.hpke")

	// Add the tag size to the protocol.
	hpke.MetaAD(protocol.LittleEndianU32(internal.TagSize))

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
		return nil, err
	}

	// Calculate the ephemeral shared secret between the recipient's private key and the ephemeral
	// public key. N.B.: this value is derived from the unauthenticated ephemeral public key.
	zzE := ristretto255.NewElement().ScalarMult(dR, qE)

	// Key the protocol with the ephemeral shared secret.
	hpke.KEY(zzE.Encode(buf[:0]))

	// Decrypt the plaintext. N.B.: this value has only been decrypted and not authenticated.
	plaintext := hpke.RecvENC(dst, ciphertext[internal.ElementSize:len(ciphertext)-internal.TagSize])

	// Verify the MAC. This establishes authentication for the previous operations in their
	// entirety, since the sender and receiver's protocol states must be identical in order for the
	// MACs to agree.
	if err := hpke.RecvMAC(ciphertext[len(ciphertext)-internal.TagSize:]); err != nil {
		return nil, err
	}

	// Return the authenticated plaintext.
	return plaintext, nil
}

// Package kemkdf provides the underlying STROBE protocol for Veil's KEM KDF function.
//
// Key encapsulation generates an ephemeral key pair, d_e and Q_e, and uses the sender's key pair,
// d_s and Q_s, and the receiver's public key, Q_r, to calculate two Diffie-Hellman shared secret
// elements, ZZ_e and ZZ_s:
//
//     ZZ_e = d_eQ_r
//     ZZ_s = d_sQ_r
//
// The ephemeral element Q_e is sent in clear text, along with data encrypted symmetrically with a
// derived key.
//
// Key derivation is as follows, given a protocol name P, an ephemeral shared secret element ZZ_e, a
// static shared secret element ZZ_s, the ephemeral public key Q_e, the recipient's public key Q_r,
// the sender's public key Q_s, and the size of the derived key N:
//
//     INIT(P,       level=256)
//     AD(LE_U32(N), meta=true)
//     KEY(ZZ_e)
//     KEY(ZZ_s)
//     AD(Q_e)
//     AD(Q_r)
//     AD(Q_s)
//     PRF(N)
//
// The two recognized protocol identifiers are:
//
// * `veil.kdf.kem.header`, used to encrypt message headers
// * `veil.kdf.kem.message`, used to encrypt message bodies
//
// Key de-encapsulation receives the ephemeral element Q_e and a ciphertext and re-calculates the
// shared secret elements, given the recipient's private key d_r and sender's public key Q_s:
//
//     ZZ_e = d_rQ_e
//     ZZ_s = d_rQ_s
//
// The symmetric key is re-derived and the ciphertext is decrypted.
//
// As a One-Pass Unified Model `C(1e, 2s, ECC CDH)` key agreement scheme (per NIST SP 800-56A), this
// KEM provides assurance that the message was encrypted by the holder of the sender's private key.
// XDH mutability issues are mitigated by the inclusion of the ephemeral public key and the
// recipient's public key in the KDF inputs. Deriving the key from all data sent or received adds
// key-commitment with all public keys as openers.
package kemkdf

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// Send returns an ephemeral public key and a shared secret given the sender's private key, the
// sender's public key, the recipient's public key, the length of the secret in bytes, and whether
// or not this is a header key.
func Send(
	privS *ristretto255.Scalar, pubS, pubR *ristretto255.Element, n int, header bool,
) (*ristretto255.Element, []byte) {
	// Generate an ephemeral key pair.
	privE, pubE := internal.NewEphemeralKeys()

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(privE, pubR)

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(privS, pubR)

	// Derive the secret from both shared secrets plus all the inputs.
	secret := deriveKey(zzE, zzS, pubE, pubR, pubS, n, header)

	// Return the ephemeral public key and the shared secret.
	return pubE, secret
}

// Receive generates a shared secret given the recipient's private key, the recipient's public key,
// the sender's public key, the ephemeral public key, the length of the shared secret in bytes, and
// whether or not this is a header key.
func Receive(
	privR *ristretto255.Scalar, pubR, pubS, pubE *ristretto255.Element, n int, header bool,
) []byte {
	// Calculate the ephemeral shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(privR, pubE)

	// Calculate the static shared secret between the recipient's secret key and the sender's public
	// key.
	zzS := ristretto255.NewElement().ScalarMult(privR, pubS)

	// Derive the secret from both shared secrets plus all the inputs.
	return deriveKey(zzE, zzS, pubE, pubR, pubS, n, header)
}

// deriveKey returns a key derived from the given ephemeral shared secret, static shared secret,
// the ephemeral public key, the recipient's public key, the sender's public key, the length of the
// secret in bytes, and whether or not the key is for a header or a message.
func deriveKey(zzE, zzS, pubE, pubR, pubS *ristretto255.Element, n int, header bool) []byte {
	// Allocate a buffer for encoding ristretto255 elements.
	b := make([]byte, internal.ElementSize)

	// Pick a protocol name.
	proto := "veil.kem.kdf.message"
	if header {
		proto = "veil.kem.kdf.header"
	}

	// Initialize the protocol.
	kdf := internal.Strobe(proto)

	// Add the output size to the protocol.
	internal.Must(kdf.AD(internal.LittleEndianU32(n), &strobe.Options{Meta: true}))

	// Add the ephemeral shared secret to the protocol.
	internal.Must(kdf.KEY(zzE.Encode(b[:0]), false))

	// Add the static shared secret to the protocol.
	internal.Must(kdf.KEY(zzS.Encode(b[:0]), false))

	// Add the ephemeral public key to the protocol.
	internal.Must(kdf.AD(pubE.Encode(b[:0]), &strobe.Options{}))

	// Add the recipient's public key to the protocol.
	internal.Must(kdf.AD(pubR.Encode(b[:0]), &strobe.Options{}))

	// Add the sender's public key to the protocol.
	internal.Must(kdf.AD(pubS.Encode(b[:0]), &strobe.Options{}))

	// Extract an n-byte derived secret and return it.
	k := make([]byte, n)
	internal.Must(kdf.PRF(k, false))

	return k
}

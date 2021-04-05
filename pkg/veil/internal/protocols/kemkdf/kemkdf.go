// Package kemkdf provides the underlying STROBE protocol for Veil's KEM KDF function.
//
// Key derivation is as follows, given a protocol name P, an ephemeral shared secret point ZZ_e, a
// static shared secret point ZZ_s, the ephemeral public key Q_e, the recipient's public key Q_r,
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
package kemkdf

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

// DeriveKey returns a key derived from the given ephemeral shared secret, static shared secret,
// the ephemeral public key, the recipient's public key, the sender's public key, the length of the
// secret in bytes, and whether or not the key is for a header or a message.
func DeriveKey(zzE, zzS, pubE, pubR, pubS *ristretto255.Element, n int, header bool) []byte {
	// Allocate a buffer for encoding ristretto255 points.
	b := make([]byte, r255.PublicKeySize)

	// Pick a protocol name.
	proto := "veil.kem.kdf.message"
	if header {
		proto = "veil.kem.kdf.header"
	}

	// Initialize the protocol.
	kdf := protocols.New(proto)

	// Add the output size to the protocol.
	protocols.Must(kdf.AD(protocols.LittleEndianU32(n), &strobe.Options{Meta: true}))

	// Add the ephemeral shared secret to the protocol.
	protocols.Must(kdf.KEY(zzE.Encode(b[:0]), false))

	// Add the static shared secret to the protocol.
	protocols.Must(kdf.KEY(zzS.Encode(b[:0]), false))

	// Add the ephemeral public key to the protocol.
	protocols.Must(kdf.AD(pubE.Encode(b[:0]), &strobe.Options{}))

	// Add the recipient's public key to the protocol.
	protocols.Must(kdf.AD(pubR.Encode(b[:0]), &strobe.Options{}))

	// Add the sender's public key to the protocol.
	protocols.Must(kdf.AD(pubS.Encode(b[:0]), &strobe.Options{}))

	// Extract an n-byte derived secret and return it.
	k := make([]byte, n)
	protocols.Must(kdf.PRF(k, false))

	return k
}

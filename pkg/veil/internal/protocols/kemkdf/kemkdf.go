// Package kemkdf provides the underlying STROBE protocol for Veil's KEM KDF function.
//
// Key derivation is as follows, given an ephemeral shared secret point ZZ_e, a static shared secret
// point ZZ_s, the ephemeral public key Q_e, the recipient's public key Q_r, the sender's public key
// Q_s, the size of the derived key N, and an intent tag T (which can be either 'header' or
// 'message'):
//
//     INIT('veil.kdf.kem',  level=256)
//     AD(T,                 meta=true)
//     AD(BIG_ENDIAN_U32(N), meta=true)
//     AD(ZZ_e,              meta=false)
//     AD(ZZ_s,              meta=false)
//     AD(Q_e,               meta=false)
//     AD(Q_r,               meta=false)
//     AD(Q_s,               meta=false)
//     PRF(N,                streaming=false)
package kemkdf

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/sammyne/strobe"
)

// DeriveKey returns a key derived from the given ephemeral shared secret, static shared secret,
// the ephemeral public key, the recipient's public key, the sender's public key, the length of the
// secret in bytes, and whether or not the key is for a header or a message.
func DeriveKey(zzE, zzS []byte, pubE, pubR, pubS *r255.PublicKey, n int, header bool) []byte {
	// Allocate a buffer for encoding ristretto255 points.
	b := make([]byte, r255.PublicKeySize)

	// Initialize the protocol.
	s, err := strobe.New("veil.kdf.kem", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	// Add the intent tag to the protocol.
	if err := s.AD(intentTag(header), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Add the output size to the protocol.
	if err := s.AD(protocols.BigEndianU32(n), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Add the ephemeral shared secret to the protocol.
	if err := s.AD(zzE, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Add the static shared secret to the protocol.
	if err := s.AD(zzS, &strobe.Options{}); err != nil {
		panic(err)
	}

	// Add the ephemeral public key to the protocol.
	if err := s.AD(pubE.Encode(b[:0]), &strobe.Options{}); err != nil {
		panic(err)
	}

	// Add the recipient's public key to the protocol.
	if err := s.AD(pubR.Encode(b[:0]), &strobe.Options{}); err != nil {
		panic(err)
	}

	// Add the sender's public key to the protocol.
	if err := s.AD(pubS.Encode(b[:0]), &strobe.Options{}); err != nil {
		panic(err)
	}

	// Extract an n-byte derived secret and return it.
	k := make([]byte, n)
	if err := s.PRF(k, false); err != nil {
		panic(err)
	}

	return k
}

func intentTag(header bool) []byte {
	if header {
		return []byte("header")
	}

	return []byte("message")
}

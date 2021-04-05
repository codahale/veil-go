// Package authenc provides the underlying STROBE protocols for Veil's authenticated encryption.
//
// Encryption of a message header is performed as follows, given a key K, an ephemeral public key Q,
// a plaintext header H, and a tag size T:
//
//     INIT('veil.authenc.header', level=256)
//     AD(LE_U32(T)),              meta=true)
//     KEY(K)
//     SEND_CLR(Q)
//     SEND_ENC(H)
//     SEND_MAC(T)
//
// The ciphertext and T-byte tag are then returned.
//
// Encryption of a secret key is performed as follows, given a key K, a secret key R, and a tag size
// T:
//
//     INIT('veil.authenc.secret-key', level=256)
//     AD(LE_U32(T)),                  meta=true)
//     KEY(K)
//     SEND_ENC(R)
//     SEND_MAC(T)
//
// The ciphertext and T-byte tag are then returned.
//
// Decryption of both is the same as encryption with RECV_* in place of SEND_* calls. No plaintext
// is returned without a successful RECV_MAC call.
//
// Encryption and decryption of message streams are initialized as follows, given a key K, block
// size B, and tag size T:
//
//     INIT('veil.authenc.stream', level=256)
//     AD(LE_U32(B)),              meta=true)
//     AD(LE_U32(T)),              meta=true)
//     KEY(K)
//
// Encrypt begins by witnessing the encrypted headers, H:
//
//     SEND_CLR(H)
//
// Encryption of an intermediate plaintext block, P, is as follows:
//
//     SEND_ENC(P)
//     SEND_MAC(T)
//     RATCHET(32)
//
// The ciphertext and T-byte tag are then written.
//
// Encryption of the final plaintext block, P, is as follows:
//
//     AD('final', meta=true)
//     SEND_ENC(P)
//     SEND_MAC(T)
//     RATCHET(32)
//
// Decryption of a stream is the same as encryption with RECV_* in place of SEND_* calls. No
// plaintext block is written to its destination without a successful RECV_MAC call.
package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

//nolint:gosec // these are not secrets, dummy
const (
	KeySize = 32 // KeySize is the symmetric key size in bytes.
	TagSize = 16 // TagSize is the authentication tag size in bytes.

	headerProto    = "veil.authenc.header"
	secretKeyProto = "veil.authenc.secret-key"
)

func newProtocol(protocol string, key []byte, tagSize int) *strobe.Strobe {
	// Create a new protocol.
	authenc := protocols.New(protocol)

	// Add the tag size to the protocol.
	protocols.Must(authenc.AD(protocols.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Copy the key.
	k := make([]byte, len(key))
	copy(k, key)

	// Initialize the protocol with the key.
	protocols.Must(authenc.KEY(k, false))

	return authenc
}

// Package stream provides the underlying STROBE protocol for Veil's streaming AEAD encryption.
//
// Encryption and decryption are initialized as follows, given a key K, associated data D, block
// size B, and tag size T:
//
//     INIT('veil.stream', level=256)
//     AD(LE_U32(B)),      meta=true)
//     AD(LE_U32(T)),      meta=true)
//     KEY(K)
//     AD(D)
//
// Encryption of an intermediate plaintext block, P, is as follows:
//
//     RATCHET(32)
//     SEND_ENC(P)
//     SEND_MAC(T)
//
// The ciphertext and T-byte tag are then written.
//
// Encryption of the final plaintext block, P, is as follows:
//
//     AD('final', meta=true)
//     RATCHET(32)
//     SEND_ENC(P)
//     SEND_MAC(T)
//
// Decryption of a stream is the same as encryption with RECV_ENC and RECV_MAC in place of SEND_ENC
// and RECV_ENC, respectively. No plaintext block is written to its destination without a successful
// RECV_MAC call.
package stream

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

// Protocol wraps all state for Veil's streaming AEAD STROBE protocol.
type Protocol struct {
	stream *strobe.Strobe
	b, tag []byte
}

// New creates a new streaming AEAD protocol with the given key, associated data, block size, and
// tag size.
func New(key, associatedData []byte, blockSize, tagSize int) *Protocol {
	// Initialize a new AEAD stream protocol.
	stream := protocols.New("veil.stream")

	// Add the block size to the protocol.
	protocols.Must(stream.AD(protocols.LittleEndianU32(blockSize), &strobe.Options{Meta: true}))

	// Add the tag size to the protocol.
	protocols.Must(stream.AD(protocols.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Copy the key.
	k := make([]byte, len(key))
	copy(k, key)

	// Initialize the protocol with the given key.
	protocols.Must(stream.KEY(k, false))

	// Add the authenticated data to the protocol.
	protocols.Must(stream.AD(associatedData, &strobe.Options{}))

	return &Protocol{
		stream: stream,
		b:      make([]byte, blockSize),
		tag:    make([]byte, tagSize),
	}
}

// Encrypt ratchets the protocol's state, encrypts the plaintext, appends an authentication tag,
// and returns the result. If this is is the last block in the stream, final must be true.
func (p *Protocol) Encrypt(block []byte, final bool) []byte {
	// Ratchet the protocol.
	p.ratchet(final)

	// Copy the input to the stream's buffer.
	copy(p.b, block)

	// Encrypt it in place.
	protocols.MustENC(p.stream.SendENC(p.b[:len(block)], &strobe.Options{}))

	// Create a MAC.
	protocols.Must(p.stream.SendMAC(p.tag, &strobe.Options{}))

	// Make a copy of the ciphertext and tag and return them.
	ciphertext := make([]byte, len(block), len(block)+len(p.tag))
	copy(ciphertext, p.b[:len(block)])

	return append(ciphertext, p.tag...)
}

// Decrypt ratchets the protocol's state, decrypts the plaintext, detaches the authentication tag,
// verifies it, and returns the plaintext. If this is is the last block in the stream, final must be
// true. If the inputs are not exactly the same as the outputs of Encrypt, an error will be
// returned.
func (p *Protocol) Decrypt(block []byte, final bool) ([]byte, error) {
	// Ratchet the protocol.
	p.ratchet(final)

	// Copy the input to the stream's buffer.
	n := len(block) - len(p.tag)
	copy(p.tag, block[n:])
	copy(p.b, block[:n])

	// Decrypt it in place.
	protocols.MustENC(p.stream.RecvENC(p.b[:n], &strobe.Options{}))

	// Check the MAC.
	if err := p.stream.RecvMAC(p.tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Make a copy of the plaintext and return it.
	plaintext := make([]byte, n)
	copy(plaintext, p.b[:n])

	return plaintext, nil
}

// ratchet advances the state of the protocol to provide perfect forward security on a
// block-by-block basis. If final is true, the state is updated with a finalization tag before the
// ratchet, permanently altering its output and preventing attackers from appending blocks.
func (p *Protocol) ratchet(final bool) {
	// If this is the final block, mark that in the stream metadata.
	if final {
		protocols.Must(p.stream.AD([]byte(finalizationTag), &strobe.Options{Meta: true}))
	}

	// Ratchet the stream.
	protocols.Must(p.stream.RATCHET(protocols.RatchetSize))
}

const (
	// finalizationTag is the associated data used to finalize the ratchet chain.
	finalizationTag = "final"
)

// Package stream provides the underlying STROBE protocol for Veil's streaming AEAD encryption.
//
// Encryption and decryption are initialized as follows, given a key K, associated data D, block
// size B, and tag size T:
//
//     INIT('veil.stream',    level=256)
//     AD(BIG_ENDIAN_U32(B)), meta=true, streaming=false)
//     AD(BIG_ENDIAN_U32(T)), meta=true, streaming=false)
//     KEY(K,                 streaming=false)
//     AD(D,                  meta=false, streaming=false)
//
// Encryption of an intermediate plaintext block, P, is as follows:
//
//     RATCHET(32)
//     SEND_ENC(P, meta=false, streaming=false)
//     SEND_MAC(T, meta=false, streaming=false)
//
// The ciphertext and 16-byte tag are then written.
//
// Encryption of the final plaintext block, P, is as follows:
//
//     AD('final', meta=true)
//     RATCHET(32)
//     SEND_ENC(P, meta=false, streaming=false)
//     SEND_MAC(T, meta=false, streaming=false)
//
// Decryption of a stream is the same as encryption with RECV_ENC and RECV_MAC in place of SEND_ENC
// and RECV_ENC, respectively. No plaintext block is written to its destination without a successful
// RECV_MAC call.
package stream

import (
	"encoding/binary"

	"github.com/sammyne/strobe"
)

// Protocol wraps all state for Veil's streaming AEAD STROBE protocol.
type Protocol struct {
	s      *strobe.Strobe
	b, tag []byte
}

// New creates a new streaming AEAD protocol with the given key, associated data, block size, and
// tag size.
func New(key, associatedData []byte, blockSize, tagSize int) *Protocol {
	// Initialize a new AEAD stream protocol.
	stream, err := strobe.New("veil.stream", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	// Add the block size to the protocol.
	if err := stream.AD(beUint32(blockSize), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Add the tag size to the protocol.
	if err := stream.AD(beUint32(tagSize), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	// Copy the key.
	k := make([]byte, len(key))
	copy(k, key)

	// Initialize the protocol with the given key.
	if err := stream.KEY(k, false); err != nil {
		panic(err)
	}

	// Add the authenticated data to the protocol.
	if err := stream.AD(associatedData, &strobe.Options{}); err != nil {
		panic(err)
	}

	return &Protocol{
		s:   stream,
		b:   make([]byte, blockSize),
		tag: make([]byte, tagSize),
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
	_, err := p.s.SendENC(p.b[:len(block)], &strobe.Options{})
	if err != nil {
		panic(err)
	}

	// Create a MAC.
	if err := p.s.SendMAC(p.tag, &strobe.Options{}); err != nil {
		panic(err)
	}

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
	_, err := p.s.RecvENC(p.b[:n], &strobe.Options{})
	if err != nil {
		panic(err)
	}

	// Check the MAC.
	if err := p.s.RecvMAC(p.tag, &strobe.Options{}); err != nil {
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
		if err := p.s.AD([]byte(finalizationTag), &strobe.Options{Meta: true}); err != nil {
			panic(err)
		}
	}

	// Ratchet the stream.
	if err := p.s.RATCHET(ratchetSize); err != nil {
		panic(err)
	}
}

// beUint32 returns n as a 32-bit big endian bit string.
func beUint32(n int) []byte {
	var b [4]byte

	binary.BigEndian.PutUint32(b[:], uint32(n))

	return b[:]
}

const (
	// finalizationTag is the associated data used to finalize the ratchet chain.
	finalizationTag = "final"

	// ratchetSize determines the amount of state to reset during each ratchet.
	//
	// > Setting L = sec/8 bytes is sufficient when R ≥ sec/8. That is, set L to 16 bytes or 32
	// > bytes for Strobe-128/b and Strobe-256/b, respectively.
	ratchetSize = int(strobe.Bit256) / 8
)

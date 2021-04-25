// Package wots provides the underlying STROBE protocol for Veil's Winternitz one-time signatures
// (W-OTS).
//
// This implementation of W-OTS creates keys and signatures with a cost/size tradeoff of 8 bits, a
// chain block size of 128 bits, and a hash size of 256 bits.
//
// Public Keys
//
// Public keys are derived from private key blocks pk_0…pk_n using another simple protocol:
//
//  INIT('veil.wots.public-key', level=256)
//  AD(LE_32(256))
//  AD(LE_32(8))
//  AD(pk_0)
//  …
//  AD(pk_n)
//  PRF(32)
//
// Signing And Verifying
//
// Blocks are created by iterating through a simple protocol:
//
//  INIT('veil.wots.block', level=256)
//  AD(LE_32(256))
//  AD(LE_32(8))
//  KEY(b)
//  PRF(16) -> b
//
// Finally, messages M_0…M_n are converted to blocks as follows, given a public key Q:
//
//  INIT('veil.wots.message', level=256)
//  AD(LE_32(256))
//  AD(LE_32(8))
//  SEND_CLR(Q)
//  SEND_CLR('',  more=false)
//  SEND_CLR(M_0, more=true)
//  …
//  SEND_CLR(M_n, more=true)
//  PRF(32)
//
// Verifying messages uses corresponding RECV_CLR operations.
//
// Security
//
// Per Buchmann et al. (https://eprint.iacr.org/2011/191.pdf), the Winternitz-Lamport-Diffie
// signature scheme is strongly unforgeable under chosen message attack in the standard model,
// assuming the underlying hash function is a PRF. This implementation is based on STROBE, which is
// constructed as a PRF.
//
// This construction adopts some of the improvements in W-OTS+ from Hülsing et al.
// (https://eprint.iacr.org/2017/965.pdf) by using families of key collision resistant PRFs (e.g.
// STROBE), allowing for a smaller chain block size (128 bits) while still preserving security.
//
// There have been additional improvements to mitigate against multi-user attacks
// (https://eprint.iacr.org/2015/1256.pdf), but given the context in which this construction is used
// (i.e. not within a post-quantum signature scheme), the simpler variant is implemented.
//
// The final variation in this implementation is the removal of an explicit message randomization
// parameter. The digest produced by veil.wots.message is dependent on the public key, which
// provides it with sufficient domain separation and misuse resistance.
package wots

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocol"
)

const (
	PublicKeySize = 32          // PublicKeySize is the size of a W-OTS public key, in bytes.
	SignatureSize = (n + 2) * n // SignatureSize is the size of a W-OTS signature, in bytes.

	n              = 16
	w              = 8
	privateKeySize = (n + 2) * n
)

type Signer struct {
	PublicKey []byte

	privateKey []byte
	p          *protocol.Protocol
	io.Writer
}

func NewSigner(dst io.Writer) (*Signer, error) {
	// Generate a random secret key.
	privateKey := make([]byte, privateKeySize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}

	// Derive the public key from the private key.
	publicKey := make([]byte, PublicKeySize)
	h := protocol.New("veil.wots.public-key")
	h.MetaAD(protocol.LittleEndianU32(n << 3))
	h.MetaAD(protocol.LittleEndianU32(w))

	for i := 0; i < len(privateKey); i += n {
		h.AD(block(privateKey[i:i+n], 1<<w))
	}

	h.PRF(publicKey)

	// Create a new protocol for the message which includes the public key.
	msg := protocol.New("veil.wots.message")
	msg.MetaAD(protocol.LittleEndianU32(n << 3))
	msg.MetaAD(protocol.LittleEndianU32(w))
	msg.SendCLR(publicKey)

	return &Signer{
		PublicKey: publicKey,

		privateKey: privateKey,
		p:          msg,
		Writer:     msg.SendCLRStream(dst),
	}, nil
}

func (s *Signer) Sign() []byte {
	// Create a digest of the signed message.
	d := make([]byte, n)
	s.p.PRF(d)
	d = checksum(d)

	// Create a signature by revealing the initial iterated hashes of the private key blocks based
	// on each byte of the message digest.
	sig := make([]byte, 0, SignatureSize)
	for i, v := range d {
		sig = append(sig, block(s.privateKey[i*n:i*n+n], int(v))...)
	}

	return sig
}

type Verifier struct {
	publicKey []byte
	p         *protocol.Protocol
	io.Writer
}

func NewVerifier(publicKey []byte) *Verifier {
	// Create a new protocol for the message which includes the public key.
	msg := protocol.New("veil.wots.message")
	msg.MetaAD(protocol.LittleEndianU32(n << 3))
	msg.MetaAD(protocol.LittleEndianU32(w))
	msg.RecvCLR(publicKey)

	return &Verifier{
		publicKey: publicKey,
		p:         msg,
		Writer:    msg.RecvCLRStream(io.Discard),
	}
}

func (v *Verifier) Verify(sig []byte) bool {
	// Check lengths.
	if len(v.publicKey) != PublicKeySize || len(sig) != SignatureSize {
		return false
	}

	// Create a digest of the signed message.
	d := make([]byte, n)
	v.p.PRF(d)
	d = checksum(d)

	// Verify the signature by using the message digest bytes to reconstitute the missing pieces
	// of the private key.
	h := protocol.New("veil.wots.public-key")
	h.MetaAD(protocol.LittleEndianU32(n << 3))
	h.MetaAD(protocol.LittleEndianU32(w))

	for i, v := range d {
		h.AD(block(sig[i*n:i*n+n], (1<<w)-int(v)))
	}

	// Re-create the public key from the re-created private key.
	publicKey := make([]byte, PublicKeySize)
	h.PRF(publicKey)

	// If the re-created public key matches, the signature was created of the message with the
	// public key's private key.
	return bytes.Equal(publicKey, v.publicKey)
}

func checksum(d []byte) []byte {
	var sum uint16
	for _, v := range d {
		sum += 256 - uint16(v)
	}

	return append(d, uint8(sum>>8), uint8(sum))
}

func block(in []byte, iterations int) []byte {
	h := protocol.New("veil.wots.block")
	h.MetaAD(protocol.LittleEndianU32(n << 3))
	h.MetaAD(protocol.LittleEndianU32(w))

	out := make([]byte, n)
	copy(out, in)

	for i := 0; i < iterations; i++ {
		b := h.Clone()
		b.KEY(out)
		b.PRF(out)
	}

	return out
}

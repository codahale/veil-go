package stream

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
)

// BlockSize is the recommended block size for streams, as selected by it looking pretty.
const BlockSize = 64 * 1024 // 64KiB

// Sealer encrypts blocks of a message stream.
//
// Encryption of a message stream is as follows, given a key K, associated data D, block size B, and
// tag size N:
//
//     INIT('veil.stream', level=256)
//     AD(LE_U32(B)),      meta=true)
//     AD(LE_U32(N)),      meta=true)
//     AD(D)
//     KEY(K)
//
// Encryption of an intermediate plaintext block P_i is as follows:
//
//     SEND_ENC(P_i)
//     SEND_MAC(N)
//     RATCHET(32)
//
// The ciphertext and N-byte tag are returned.
//
// Encryption of the final plaintext block, P_n, is as follows:
//
//     AD('final', meta=true)
//     SEND_ENC(P_n)
//     SEND_MAC(N)
//     RATCHET(32)
//
// The ciphertext and N-byte tag are returned.
type Sealer struct {
	stream *protocol.Protocol
}

// NewSealer creates a new Sealer with the given key, associated data, block size, and tag size.
func NewSealer(key, associatedData []byte) *Sealer {
	return &Sealer{
		stream: initStream(key, associatedData),
	}
}

// Seal encrypts the plaintext, appends an authentication tag, ratchets the protocol's state,
// and returns the result. If this is is the last block in the stream, final must be true.
func (s *Sealer) Seal(dst, plaintext []byte, final bool) []byte {
	// If this is the final block, mark that in the stream metadata.
	if final {
		finalizeStream(s.stream)
	}

	ret, out := internal.SliceForAppend(dst, len(plaintext)+internal.TagSize)

	// Encrypt the plaintext.
	out = s.stream.SendENC(out[:0], plaintext)

	// Create a MAC.
	s.stream.SendMAC(out, internal.TagSize)

	// Ratchet the stream.
	s.stream.Ratchet()

	// Return the ciphertext and tag.
	return ret
}

// Opener decrypts blocks of a message stream.
//
// Decryption of a message stream is as follows, given a key K, associated data D, block size B, and
// tag size N:
//
//     INIT('veil.stream', level=256)
//     AD(LE_U32(B)),      meta=true)
//     AD(LE_U32(N)),      meta=true)
//     AD(D)
//     KEY(K)
//
// Decryption of an intermediate ciphertext block C_i and authentication tag T_i is as follows:
//
//     RECV_ENC(C_i)
//     RECV_MAC(T_i)
//     RATCHET(32)
//
// If the RECV_MAC operation is successful, the plaintext block is returned.
//
// Decryption of the final ciphertext block P_n and authentication tag T_n is as follows:
//
//     AD('final', meta=true)
//     RECV_ENC(C_n)
//     RECV_MAC(T_n)
//     RATCHET(32)
//
// If the RECV_MAC operation is successful, the plaintext block is returned.
type Opener struct {
	stream *protocol.Protocol
}

// NewOpener creates a new Opener with the given key, associated data, block size, and tag size.
func NewOpener(key, associatedData []byte) *Opener {
	return &Opener{
		stream: initStream(key, associatedData),
	}
}

// Open decrypts the ciphertext, detaches the authentication tag, verifies it, ratchets the
// protocol's state, and returns the plaintext. If this is is the last block in the stream, final
// must be true. If the inputs are not exactly the same as the outputs of Seal, an error will be
// returned.
func (s *Opener) Open(dst, ciphertext []byte, final bool) ([]byte, error) {
	// If this is the final block, mark that in the stream metadata.
	if final {
		finalizeStream(s.stream)
	}

	// Decrypt the block.
	plaintext := s.stream.RecvENC(dst, ciphertext[:len(ciphertext)-internal.TagSize])

	// Check the MAC.
	if err := s.stream.RecvMAC(ciphertext[len(ciphertext)-internal.TagSize:]); err != nil {
		return nil, err
	}

	// Ratchet the stream.
	s.stream.Ratchet()

	return plaintext, nil
}

func initStream(key, associatedData []byte) *protocol.Protocol {
	// Initialize a new stream protocol.
	stream := protocol.New("veil.stream")

	// Add the block size to the protocol.
	stream.AD(protocol.LittleEndianU32(BlockSize), protocol.Meta)

	// Add the tag size to the protocol.
	stream.AD(protocol.LittleEndianU32(internal.TagSize), protocol.Meta)

	// Add the associated data to the protocol.
	stream.AD(associatedData)

	// Initialize the protocol with the given key.
	stream.Key(key)

	return stream
}

func finalizeStream(stream *protocol.Protocol) {
	stream.AD([]byte("final"), protocol.Meta)
}

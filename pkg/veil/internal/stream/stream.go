package stream

import (
	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/sammyne/strobe"
)

// Sealer encrypts blocks of a message stream.
//
// Encryption of a message stream is as follows, given a key K, block size B, and tag size N:
//
//     INIT('veil.stream', level=256)
//     AD(LE_U32(B)),      meta=true)
//     AD(LE_U32(N)),      meta=true)
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
	stream *strobe.Strobe
	b, tag []byte
}

// NewSealer creates a new Sealer with the given key, block size, and tag size.
func NewSealer(key []byte, blockSize, tagSize int) *Sealer {
	return &Sealer{
		stream: initStream(key, blockSize, tagSize),
		b:      make([]byte, blockSize),
		tag:    make([]byte, tagSize),
	}
}

// Seal encrypts the plaintext, appends an authentication tag, ratchets the protocol's state,
// and returns the result. If this is is the last block in the stream, final must be true.
func (s *Sealer) Seal(plaintext []byte, final bool) []byte {
	// If this is the final block, mark that in the stream metadata.
	if final {
		finalizeStream(s.stream)
	}

	// Copy the input to the stream's buffer.
	copy(s.b, plaintext)

	// Encrypt it in place.
	internal.MustENC(s.stream.SendENC(s.b[:len(plaintext)], &strobe.Options{}))

	// Create a MAC.
	internal.Must(s.stream.SendMAC(s.tag, &strobe.Options{}))

	// Ratchet the stream.
	internal.Must(s.stream.RATCHET(internal.RatchetSize))

	// Return the ciphertext and tag.
	return append(s.b[:len(plaintext)], s.tag...)
}

// Opener decrypts blocks of a message stream.
//
// Decryption of a message stream is as follows, given a key K, block size B, and tag size N:
//
//     INIT('veil.stream', level=256)
//     AD(LE_U32(B)),      meta=true)
//     AD(LE_U32(N)),      meta=true)
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
	stream *strobe.Strobe
	b, tag []byte
}

// NewOpener creates a new Opener with the given key, block size, and tag size.
func NewOpener(key []byte, blockSize, tagSize int) *Opener {
	return &Opener{
		stream: initStream(key, blockSize, tagSize),
		b:      make([]byte, blockSize),
		tag:    make([]byte, tagSize),
	}
}

// Open decrypts the ciphertext, detaches the authentication tag, verifies it, ratchets the
// protocol's state, and returns the plaintext. If this is is the last block in the stream, final
// must be true. If the inputs are not exactly the same as the outputs of Seal, an error will be
// returned.
func (s *Opener) Open(ciphertext []byte, final bool) ([]byte, error) {
	// If this is the final block, mark that in the stream metadata.
	if final {
		finalizeStream(s.stream)
	}

	// Copy the input to the stream's buffer.
	n := len(ciphertext) - len(s.tag)
	copy(s.tag, ciphertext[n:])
	copy(s.b, ciphertext[:n])

	// Decrypt it in place.
	internal.MustENC(s.stream.RecvENC(s.b[:n], &strobe.Options{}))

	// Check the MAC.
	if err := s.stream.RecvMAC(s.tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Ratchet the stream.
	internal.Must(s.stream.RATCHET(internal.RatchetSize))

	// Make a copy of the plaintext and return it.
	plaintext := make([]byte, n)
	copy(plaintext, s.b[:n])

	return plaintext, nil
}

func initStream(key []byte, blockSize, tagSize int) *strobe.Strobe {
	// Initialize a new stream protocol.
	stream := internal.Strobe("veil.stream")

	// Add the block size to the protocol.
	internal.Must(stream.AD(internal.LittleEndianU32(blockSize), &strobe.Options{Meta: true}))

	// Add the tag size to the protocol.
	internal.Must(stream.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Initialize the protocol with the given key.
	internal.Must(stream.KEY(internal.Copy(key), false))

	return stream
}

func finalizeStream(stream *strobe.Strobe) {
	internal.Must(stream.AD([]byte(("final")), &strobe.Options{Meta: true}))
}

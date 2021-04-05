package authenc

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

// StreamEncrypter encrypts blocks of a message stream.
type StreamEncrypter struct {
	stream *strobe.Strobe
	b, tag []byte
}

func NewStreamEncrypter(key, encryptedHeaders []byte, blockSize, tagSize int) *StreamEncrypter {
	stream := initStream(key, blockSize, tagSize)

	// Witness the encrypted headers.
	protocols.Must(stream.SendCLR(encryptedHeaders, &strobe.Options{}))

	return &StreamEncrypter{
		stream: stream,
		b:      make([]byte, blockSize),
		tag:    make([]byte, tagSize),
	}
}

// Encrypt encrypts the plaintext, appends an authentication tag, ratchets the protocol's state,
// and returns the result. If this is is the last block in the stream, final must be true.
func (s *StreamEncrypter) Encrypt(block []byte, final bool) []byte {
	// If this is the final block, mark that in the stream metadata.
	if final {
		finalizeStream(s.stream)
	}

	// Copy the input to the stream's buffer.
	copy(s.b, block)

	// Encrypt it in place.
	protocols.MustENC(s.stream.SendENC(s.b[:len(block)], &strobe.Options{}))

	// Create a MAC.
	protocols.Must(s.stream.SendMAC(s.tag, &strobe.Options{}))

	// Ratchet the stream.
	protocols.Must(s.stream.RATCHET(protocols.RatchetSize))

	// Return the ciphertext and tag.
	return append(s.b[:len(block)], s.tag...)
}

// StreamDecrypter decrypts blocks of a message stream.
type StreamDecrypter struct {
	stream *strobe.Strobe
	b, tag []byte
}

// NewStreamDecrypter creates a new streaming AEAD decrypter with the given key, encrypted headers,
// block size, and tag size.
func NewStreamDecrypter(key, encryptedHeaders []byte, blockSize, tagSize int) *StreamDecrypter {
	stream := initStream(key, blockSize, tagSize)

	// Witness the encrypted headers.
	protocols.Must(stream.RecvCLR(encryptedHeaders, &strobe.Options{}))

	return &StreamDecrypter{
		stream: stream,
		b:      make([]byte, blockSize),
		tag:    make([]byte, tagSize),
	}
}

// Decrypt decrypts the plaintext, detaches the authentication tag, verifies it, ratchets the
// protocol's state, and returns the plaintext. If this is is the last block in the stream, final
// must be true. If the inputs are not exactly the same as the outputs of Encrypt, an error will be
// returned.
func (s *StreamDecrypter) Decrypt(block []byte, final bool) ([]byte, error) {
	// If this is the final block, mark that in the stream metadata.
	if final {
		finalizeStream(s.stream)
	}

	// Copy the input to the stream's buffer.
	n := len(block) - len(s.tag)
	copy(s.tag, block[n:])
	copy(s.b, block[:n])

	// Decrypt it in place.
	protocols.MustENC(s.stream.RecvENC(s.b[:n], &strobe.Options{}))

	// Check the MAC.
	if err := s.stream.RecvMAC(s.tag, &strobe.Options{}); err != nil {
		return nil, err
	}

	// Ratchet the stream.
	protocols.Must(s.stream.RATCHET(protocols.RatchetSize))

	// Make a copy of the plaintext and return it.
	plaintext := make([]byte, n)
	copy(plaintext, s.b[:n])

	return plaintext, nil
}

func initStream(key []byte, blockSize, tagSize int) *strobe.Strobe {
	// Initialize a new AEAD stream protocol.
	stream := protocols.New("veil.authenc.stream")

	// Add the block size to the protocol.
	protocols.Must(stream.AD(protocols.LittleEndianU32(blockSize), &strobe.Options{Meta: true}))

	// Add the tag size to the protocol.
	protocols.Must(stream.AD(protocols.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Copy the key.
	k := make([]byte, len(key))
	copy(k, key)

	// Initialize the protocol with the given key.
	protocols.Must(stream.KEY(k, false))

	return stream
}

func finalizeStream(stream *strobe.Strobe) {
	protocols.Must(stream.AD([]byte(finalizationTag), &strobe.Options{Meta: true}))
}

const (
	// finalizationTag is the associated data used to finalize the ratchet chain.
	finalizationTag = "final"
)

package veil

import (
	"crypto/cipher"
	"io"

	"github.com/google/tink/go/streamingaead/subtle/noncebased"
	"golang.org/x/crypto/chacha20poly1305"
)

const noncePrefixLen = chacha20poly1305.NonceSize - 5

// newAEADReader returns an io.Writer which encrypts writes using ChaCha20Poly1305 with the given
// key and nonce and writes ciphertext to dst.
func newAEADWriter(dst io.Writer, key, noncePrefix, ad []byte) (io.WriteCloser, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return noncebased.NewWriter(noncebased.WriterParams{
		W:                            dst,
		SegmentEncrypter:             &chachaSegment{aead: aead, ad: ad},
		NonceSize:                    chacha20poly1305.NonceSize,
		NoncePrefix:                  noncePrefix[:noncePrefixLen],
		PlaintextSegmentSize:         blockSize,
		FirstCiphertextSegmentOffset: 0,
	})
}

// newAEADReader returns an io.Reader which decrypts src using ChaCha20Poly1305 with the given key
// and nonce.
func newAEADReader(src io.Reader, key, noncePrefix, ad []byte) (io.Reader, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return noncebased.NewReader(noncebased.ReaderParams{
		R:                            src,
		SegmentDecrypter:             &chachaSegment{aead: aead, ad: ad},
		NonceSize:                    chacha20poly1305.NonceSize,
		NoncePrefix:                  noncePrefix[:noncePrefixLen],
		CiphertextSegmentSize:        blockSize,
		FirstCiphertextSegmentOffset: 0,
	})
}

// chachaSegment encrypts and decrypts segments using ChaCha20Poly1305.
type chachaSegment struct {
	aead cipher.AEAD
	ad   []byte
}

func (c *chachaSegment) EncryptSegment(segment, nonce []byte) ([]byte, error) {
	return c.aead.Seal(nil, nonce, segment, c.ad), nil
}

func (c *chachaSegment) DecryptSegment(segment, nonce []byte) ([]byte, error) {
	return c.aead.Open(nil, nonce, segment, c.ad)
}

var (
	_ noncebased.SegmentDecrypter = &chachaSegment{}
	_ noncebased.SegmentEncrypter = &chachaSegment{}
)

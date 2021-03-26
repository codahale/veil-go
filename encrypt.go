package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/codahale/veil/internal/kem"
	"github.com/codahale/veil/internal/ratchet"
	"github.com/codahale/veil/internal/stream"
	"github.com/codahale/veil/internal/xdh"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes written and the first
// error reported while encrypting, if any.
func (sk *SecretKey) Encrypt(dst io.Writer, src io.Reader, recipients []*PublicKey, padding int) (int64, error) {
	// Generate an ephemeral key pair.
	pkE, _, skE, err := xdh.GenerateKeys()
	if err != nil {
		return 0, err
	}

	// Encode the ephemeral secret key and offset into a header.
	offset := encryptedHeaderSize*len(recipients) + padding
	header := make([]byte, headerSize)
	copy(header, skE.Bytes())
	binary.BigEndian.PutUint32(header[xdh.PublicKeySize:], uint32(offset))

	// Encrypt copies of the header for each recipient.
	headers, err := sk.encryptHeaders(header, recipients, padding)
	if err != nil {
		return 0, err
	}

	// Write the encrypted headers.
	n, err := dst.Write(headers)
	if err != nil {
		return int64(n), err
	}

	// Generate a shared ratchet key between the sender and the ephemeral key.
	rkW, key, err := kem.Send(&sk.s, &sk.pk.q, &pkE, []byte("message"), ratchet.KeySize)
	if err != nil {
		return int64(n), err
	}

	// Write the wrapper Elligator2 representative.
	an, err := dst.Write(rkW)
	if err != nil {
		return int64(n + an), err
	}

	// Initialize an AEAD writer with the ratchet key, using the encrypted headers as authenticated
	// data.
	w := stream.NewWriter(dst, key, headers, blockSize)

	// Encrypt the plaintext as a stream.
	bn, err := io.Copy(w, src)
	if err != nil {
		return bn + int64(n+an), err
	}

	// Return the bytes written and flush any buffers.
	return bn + int64(n+an), w.Close()
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func (sk *SecretKey) encryptHeaders(header []byte, publicKeys []*PublicKey, padding int) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(header)*len(publicKeys)))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		// Generate a shared secret for the recipient.
		rkE, secret, err := kem.Send(&sk.s, &sk.pk.q, &pkR.q, []byte("header"), chacha20.KeySize+chacha20.NonceSize)
		if err != nil {
			return nil, err
		}

		// Initialize a ChaCha20Poly1305 AEAD.
		aead, err := chacha20poly1305.New(secret[:chacha20.KeySize])
		if err != nil {
			panic(err)
		}

		// Encrypt the header for the recipient.
		b := aead.Seal(nil, secret[chacha20.KeySize:], header, nil)

		// Write the ephemeral representative and the ciphertext.
		_, _ = buf.Write(rkE)
		_, _ = buf.Write(b)
	}

	// Add padding if any is required.
	if padding > 0 {
		if _, err := io.CopyN(buf, rand.Reader, int64(padding)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

const (
	blockSize           = 64 * 1024             // 64KiB
	headerSize          = xdh.PublicKeySize + 4 // 4 bytes for message offset
	encryptedHeaderSize = xdh.PublicKeySize + headerSize + poly1305.TagSize
)

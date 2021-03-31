package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/codahale/veil/internal/kem"
	"github.com/codahale/veil/internal/r255"
	"github.com/codahale/veil/internal/ratchet"
	"github.com/codahale/veil/internal/scopedhash"
	"github.com/codahale/veil/internal/stream"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes written and the first
// error reported while encrypting, if any.
func (sk SecretKey) Encrypt(dst io.Writer, src io.Reader, recipients []PublicKey, padding int) (int64, error) {
	// Generate an ephemeral header key pair.
	skEH, err := r255.NewSecretKey()
	if err != nil {
		return 0, err
	}

	pkEH := r255.PublicKey(skEH)

	// Encode the ephemeral header secret key and offset into a header.
	header := sk.encodeHeader(skEH, len(recipients), padding)

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

	// Generate an ephemeral message public key and shared secret between the sender and the
	// ephemeral header public key.
	pkEM, key, err := kem.Send(sk, sk.PublicKey(), pkEH, []byte("message"), ratchet.KeySize)
	if err != nil {
		return int64(n), err
	}

	// Write the ephemeral message public key.
	an, err := dst.Write(pkEM)
	if err != nil {
		return int64(n + an), err
	}

	// Initialize an AEAD writer with the ratchet key, using the encrypted headers as authenticated
	// data.
	w := stream.NewWriter(dst, key, headers, blockSize)

	// Tee reads from the input into a SHA-512 hash.
	h := scopedhash.NewMessageHash()
	r := io.TeeReader(src, h)

	// Encrypt the plaintext as a stream.
	bn, err := io.Copy(w, r)
	if err != nil {
		return bn + int64(n+an), err
	}

	// Create a signature of the SHA-512 hash of the plaintext.
	sig, err := r255.Sign(sk, h.Sum(nil))
	if err != nil {
		return bn + int64(n+an), err
	}

	// Append the signature to the plaintext.
	cn, err := w.Write(sig)
	if err != nil {
		return bn + int64(n+an+cn), err
	}

	// Return the bytes written and flush any buffers.
	return bn + int64(n+an+cn), w.Close()
}

// encodeHeader encodes the ephemeral header secret key and the message offset.
func (sk SecretKey) encodeHeader(skEH []byte, recipients, padding int) []byte {
	// Copy the secret key.
	header := make([]byte, headerSize)
	copy(header, skEH)

	// Calculate the message offset and encode it.
	offset := encryptedHeaderSize*recipients + padding
	binary.BigEndian.PutUint32(header[r255.SecretKeySize:], uint32(offset))

	return header
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func (sk SecretKey) encryptHeaders(header []byte, publicKeys []PublicKey, padding int) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(header)*len(publicKeys)))

	// Re-derive the sender's public key.
	pk := sk.PublicKey()

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		// Generate a header key pair shared secret for the recipient.
		pkEH, secret, err := kem.Send(sk, pk, pkR, []byte("header"), chacha20.KeySize+chacha20.NonceSize)
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

		// Write the ephemeral header public key and the ciphertext.
		_, _ = buf.Write(pkEH)
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
	blockSize           = 64 * 1024              // 64KiB
	headerSize          = r255.SecretKeySize + 4 // 4 bytes for message offset
	encryptedHeaderSize = r255.PublicKeySize + headerSize + poly1305.TagSize
)

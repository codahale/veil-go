package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/dxof"
	"github.com/codahale/veil/pkg/veil/internal/kem"
	"github.com/codahale/veil/pkg/veil/internal/protocols/authenc"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/codahale/veil/pkg/veil/internal/streamio"
)

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes written and the first
// error reported while encrypting, if any.
func (pk *PrivateKey) Encrypt(dst io.Writer, src io.Reader, recipients []*PublicKey, padding int) (int64, error) {
	// Re-derive the sender's public key.
	pubS := pk.k.PublicKey()

	// Generate an ephemeral header key pair.
	privEH, pubEH, err := r255.NewEphemeralKeys()
	if err != nil {
		return 0, err
	}

	// Encode the ephemeral header private key and offset into a header.
	header := pk.encodeHeader(privEH, len(recipients), padding)

	// Encrypt copies of the header for each recipient.
	headers, err := pk.encryptHeaders(pubS, header, recipients, padding)
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
	pubEM, key, err := kem.Send(pk.k, pubS, pubEH, authenc.KeySize, false)
	if err != nil {
		return int64(n), err
	}

	// Write the ephemeral message public key.
	an, err := dst.Write(pubEM.Encode(nil))
	if err != nil {
		return int64(n + an), err
	}

	// Initialize an AEAD writer with the ratchet key, using the encrypted headers as authenticated
	// data.
	w := streamio.NewWriter(dst, key, headers, blockSize)

	// Tee reads from the input into an XOF.
	xof := dxof.MessageDigest()
	r := io.TeeReader(src, xof)

	// Encrypt the plaintext as a stream.
	bn, err := io.Copy(w, r)
	if err != nil {
		return bn + int64(n+an), err
	}

	// Calculate the digest of the plaintext.
	digest := make([]byte, digestSize)
	_, _ = io.ReadFull(xof, digest)

	// Create a signature of the digest.
	sig := pk.k.Sign(digest)

	// Append the signature to the plaintext.
	cn, err := w.Write(sig)
	if err != nil {
		return bn + int64(n+an+cn), err
	}

	// Return the bytes written and flush any buffers.
	return bn + int64(n+an+cn), w.Close()
}

// encodeHeader encodes the ephemeral header private key and the message offset.
func (pk *PrivateKey) encodeHeader(privEH *r255.PrivateKey, recipients, padding int) []byte {
	// Copy the private key.
	header := make([]byte, headerSize)
	copy(header, privEH.Encode(nil))

	// Calculate the message offset and encode it.
	offset := encryptedHeaderSize*recipients + padding
	binary.BigEndian.PutUint32(header[r255.PrivateKeySize:], uint32(offset))

	return header
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func (pk *PrivateKey) encryptHeaders(
	pubS *r255.PublicKey, header []byte, publicKeys []*PublicKey, padding int,
) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(header)*len(publicKeys)))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		// Generate a header ephemeral key and shared key for the recipient.
		pubEH, key, err := kem.Send(pk.k, pubS, pkR.k, authenc.KeySize, true)
		if err != nil {
			return nil, err
		}

		// Encrypt the header for the recipient.
		b := authenc.EncryptHeader(key, header, authenc.TagSize)

		// Write the ephemeral header public key and the ciphertext.
		_, _ = buf.Write(pubEH.Encode(nil))
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
	blockSize           = 64 * 1024               // 64KiB
	headerSize          = r255.PrivateKeySize + 4 // 4 bytes for message offset
	encryptedHeaderSize = r255.PublicKeySize + headerSize + authenc.TagSize
)

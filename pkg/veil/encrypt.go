package veil

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols/authenc"
	"github.com/codahale/veil/pkg/veil/internal/protocols/authenc/streamio"
	"github.com/codahale/veil/pkg/veil/internal/protocols/kemkdf"
	"github.com/codahale/veil/pkg/veil/internal/protocols/msghash"
	"github.com/codahale/veil/pkg/veil/internal/protocols/rng"
	"github.com/codahale/veil/pkg/veil/internal/protocols/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
)

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes written and the first
// error reported while encrypting, if any.
func (pk *PrivateKey) Encrypt(dst io.Writer, src io.Reader, recipients []*PublicKey, padding int) (int64, error) {
	// Generate an ephemeral header key pair.
	privEH, pubEH, err := rng.NewEphemeralKeys()
	if err != nil {
		return 0, err
	}

	// Encode the ephemeral header private key and offset into a header.
	header := pk.encodeHeader(privEH, len(recipients), padding)

	// Encrypt copies of the header for each recipient.
	headers, err := pk.encryptHeaders(header, recipients, padding)
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
	pubEM, key, err := kemkdf.Send(pk.d, pk.q, pubEH, authenc.KeySize, false)
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

	// Tee reads from the input into the msghash STROBE protocol.
	h := msghash.NewWriter(digestSize)
	r := io.TeeReader(src, h)

	// Encrypt the plaintext as a stream.
	bn, err := io.Copy(w, r)
	if err != nil {
		return bn + int64(n+an), err
	}

	// Create a signature of the digest of the plaintext.
	sig := schnorr.Sign(pk.d, pk.q, h.Digest())

	// Append the signature to the plaintext.
	cn, err := w.Write(sig)
	if err != nil {
		return bn + int64(n+an+cn), err
	}

	// Return the bytes written and flush any buffers.
	return bn + int64(n+an+cn), w.Close()
}

// encodeHeader encodes the ephemeral header private key and the message offset.
func (pk *PrivateKey) encodeHeader(privEH *ristretto255.Scalar, recipients, padding int) []byte {
	// Copy the private key.
	header := make([]byte, headerSize)
	copy(header, privEH.Encode(nil))

	// Calculate the message offset and encode it.
	offset := encryptedHeaderSize*recipients + padding
	binary.LittleEndian.PutUint32(header[r255.ScalarSize:], uint32(offset))

	return header
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func (pk *PrivateKey) encryptHeaders(header []byte, publicKeys []*PublicKey, padding int) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(header)*len(publicKeys)))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		// Generate a header ephemeral key and shared key for the recipient.
		pubEH, key, err := kemkdf.Send(pk.d, pk.q, pkR.q, authenc.KeySize, true)
		if err != nil {
			return nil, err
		}

		// Encrypt the header for the recipient.
		b := authenc.EncryptHeader(key, pubEH, header, authenc.TagSize)

		// Write the ephemeral header public key and the ciphertext.
		_, _ = buf.Write(pubEH.Encode(nil))
		_, _ = buf.Write(b)
	}

	// Add padding if any is required.
	if padding > 0 {
		if _, err := io.CopyN(buf, rng.Reader, int64(padding)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

const (
	blockSize           = 64 * 1024           // 64KiB
	headerSize          = r255.ScalarSize + 4 // 4 bytes for message offset
	encryptedHeaderSize = r255.ElementSize + headerSize + authenc.TagSize
)

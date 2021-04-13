package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/kem"
	"github.com/codahale/veil/pkg/veil/internal/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/stream/streamio"
)

// Encrypt encrypts the data from src such that all recipients will be able to decrypt and
// authenticate it and writes the results to dst. Returns the number of bytes copied and the first
// error reported while encrypting, if any.
func (pk *PrivateKey) Encrypt(dst io.Writer, src io.Reader, recipients []*PublicKey, padding int) (int64, error) {
	// Generate a random DEK.
	dek := make([]byte, internal.DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return 0, err
	}

	// Create a signer with the DEK as associated data.
	signer := schnorr.NewSigner(pk.d, pk.q, dek)

	// Encode the DEK and offset into a header.
	header := pk.encodeHeader(dek, len(recipients), padding)

	// Encrypt copies of the header for each recipient and add random padding.
	headers, err := pk.encryptHeaders(header, recipients, padding)
	if err != nil {
		return 0, err
	}

	// Write all output to the signer as well as dst.
	out := io.MultiWriter(dst, signer)

	// Write the encrypted headers.
	_, err = out.Write(headers)
	if err != nil {
		return 0, err
	}

	// Initialize a stream writer with the DEK and the encrypted headers as associated data.
	ciphertext := streamio.NewWriter(out, dek, headers)

	// Encrypt the plaintext as a stream, and add the plaintext to the signed data.
	n, err := io.Copy(ciphertext, src)
	if err != nil {
		return n, err
	}

	// Flush all block buffers.
	if err := ciphertext.Close(); err != nil {
		return n, err
	}

	// Create a signature of the ciphertext.
	sig := signer.Sign()

	// Append the signature to the ciphertext.
	_, err = dst.Write(sig)
	if err != nil {
		return n, err
	}

	// Return the bytes copied.
	return n, nil
}

// encodeHeader encodes the DEK and the message offset.
func (pk *PrivateKey) encodeHeader(dek []byte, recipients, padding int) []byte {
	header := make([]byte, headerSize)
	copy(header, dek)

	// Calculate the message offset and encode it.
	offset := encryptedHeaderSize*recipients + padding
	binary.LittleEndian.PutUint32(header[internal.DEKSize:], uint32(offset))

	return header
}

// encryptHeaders encrypts the header for the given set of public keys and adds the given amount of
// random padding.
func (pk *PrivateKey) encryptHeaders(header []byte, publicKeys []*PublicKey, padding int) ([]byte, error) {
	buf := make([]byte, encryptedHeaderSize)
	headers := bytes.NewBuffer(make([]byte, 0, len(publicKeys)*encryptedHeaderSize))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		_, _ = headers.Write(kem.Encrypt(buf[:0], pk.d, pk.q, pkR.q, header))
	}

	// Add padding if any is required.
	if padding > 0 {
		if _, err := io.CopyN(headers, rand.Reader, int64(padding)); err != nil {
			return nil, err
		}
	}

	return headers.Bytes(), nil
}

const (
	headerSize          = internal.DEKSize + 4 // 4 bytes for message offset
	encryptedHeaderSize = headerSize + kem.Overhead
)

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
// authenticate it and writes the results to dst. Returns the number of bytes written and the first
// error reported while encrypting, if any.
func (pk *PrivateKey) Encrypt(dst io.Writer, src io.Reader, recipients []*PublicKey, padding int) (int64, error) {
	// Generate a random message key.
	key := make([]byte, internal.MessageKeySize)
	if _, err := rand.Read(key); err != nil {
		return 0, err
	}

	// Encode the message key and offset into a header.
	header := pk.encodeHeader(key, len(recipients), padding)

	// Encrypt copies of the header for each recipient and add random padding.
	headers, err := pk.encryptHeaders(header, recipients, padding)
	if err != nil {
		return 0, err
	}

	// Write the encrypted headers.
	hn, err := dst.Write(headers)
	if err != nil {
		return int64(hn), err
	}

	// Initialize a stream writer with the message key and the encrypted headers as associated data.
	encryptor := streamio.NewWriter(dst, key, headers, internal.BlockSize)

	// Create a signer with the encrypted headers as associated data.
	signer := schnorr.NewSigner(headers)

	// Encrypt the plaintext as a stream, and add the plaintext to the signed data.
	mn, err := io.Copy(io.MultiWriter(encryptor, signer), src)
	if err != nil {
		return mn + int64(hn), err
	}

	// Create a signature of the plaintext.
	sig := signer.Sign(pk.d, pk.q)

	// Append the signature to the plaintext.
	sn, err := encryptor.Write(sig)
	if err != nil {
		return mn + int64(hn+sn), err
	}

	// Return the bytes written and flush any buffers.
	return mn + int64(hn+sn), encryptor.Close()
}

// encodeHeader encodes the message key and the message offset.
func (pk *PrivateKey) encodeHeader(key []byte, recipients, padding int) []byte {
	// Copy the message key.
	header := make([]byte, headerSize)
	copy(header, key)

	// Calculate the message offset and encode it.
	offset := encryptedHeaderSize*recipients + padding
	binary.LittleEndian.PutUint32(header[internal.MessageKeySize:], uint32(offset))

	return header
}

// encryptHeaders encrypts the header for the given set of public keys with the specified number of
// fake recipients.
func (pk *PrivateKey) encryptHeaders(header []byte, publicKeys []*PublicKey, padding int) ([]byte, error) {
	// Allocate a buffer for the entire header.
	buf := bytes.NewBuffer(make([]byte, 0, len(publicKeys)*encryptedHeaderSize))

	// Encrypt a copy of the header for each recipient.
	for _, pkR := range publicKeys {
		_, _ = buf.Write(kem.Encrypt(pk.d, pk.q, pkR.q, header, internal.TagSize))
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
	headerSize          = internal.MessageKeySize + 4 // 4 bytes for message offset
	encryptedHeaderSize = headerSize + internal.TagSize
)

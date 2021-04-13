package veil

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/kem"
	"github.com/codahale/veil/pkg/veil/internal/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/schnorr/sigio"
	"github.com/codahale/veil/pkg/veil/internal/stream/streamio"
)

// Decrypt decrypts the data in src if originally encrypted by any of the given public keys. Returns
// the sender's public key, the number of decrypted bytes written, and the first reported error, if
// any.
//
// N.B.: Because Veil messages are streamed, it is possible that this may write some decrypted data
// to dst before it can discover that the ciphertext is invalid. If Decrypt returns an error, all
// output written to dst should be discarded, as it cannot be ascertained to be authentic.
func (pk *PrivateKey) Decrypt(dst io.Writer, src io.Reader, senders []*PublicKey) (*PublicKey, int64, error) {
	// Find a decryptable header and recover the DEK.
	headers, pkS, dek, err := pk.findHeader(src, senders)
	if err != nil {
		return nil, 0, err
	}

	// Initialize a stream reader with the DEK and the encrypted headers as associated data.
	plaintext := streamio.NewReader(src, dek, headers)

	// Detach the signature from the plaintext.
	sr := sigio.NewReader(plaintext)

	// Create a verifier with the encrypted headers as associated data.
	verifier := schnorr.NewVerifier(pkS.q, headers)

	// Decrypt the plaintext as a stream, adding it to the verified data.
	n, err := io.Copy(dst, io.TeeReader(sr, verifier))
	if err != nil {
		return nil, n, err
	}

	// Verify the signature of the encrypted headers and the plaintext.
	if !verifier.Verify(sr.Signature) {
		return nil, n, ErrInvalidCiphertext
	}

	// Return the sender's public key and the number of bytes written.
	return pkS, n, nil
}

// findHeader scans src for header blocks encrypted by any of the given possible senders. Returns
// the full slice of encrypted headers, the sender's public key, and the DEK if successful.
func (pk *PrivateKey) findHeader(
	src io.Reader, senders []*PublicKey,
) ([]byte, *PublicKey, []byte, error) {
	headers := make([]byte, 0, len(senders)*encryptedHeaderSize) // a guess at initial capacity
	buf := make([]byte, encryptedHeaderSize)

	for {
		// Iterate through src in header-sized blocks.
		_, err := io.ReadFull(src, buf)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// If we hit an EOF, expected and/or otherwise, this is the final block. We didn't find
			// a header we could decrypt, so the ciphertext is invalid.
			return nil, nil, nil, ErrInvalidCiphertext
		} else if err != nil {
			return nil, nil, nil, err
		}

		// Append the current header to the list of encrypted headers.
		headers = append(headers, buf...)

		// Attempt to decrypt the header.
		pkS, dek, offset := pk.decryptHeader(buf, senders)

		// If we successfully decrypt the header, use the message offset to read the remaining
		// encrypted headers.
		if pkS != nil {
			remaining := make([]byte, offset-len(headers))
			if _, err := io.ReadFull(src, remaining); err != nil {
				return nil, nil, nil, err
			}

			// Return the full set of encrypted headers, the sender's public key, and the DEK.
			return append(headers, remaining...), pkS, dek, nil
		}
	}
}

// decryptHeader attempts to decrypt the given header block if sent from any of the given public
// keys. Returns the sender's public key, the DEK, and the message offset if successful.
func (pk *PrivateKey) decryptHeader(header []byte, senders []*PublicKey) (*PublicKey, []byte, int) {
	buf := make([]byte, headerSize)

	// Iterate through all possible senders.
	for _, pubS := range senders {
		// Try to decrypt the header. If the header cannot be decrypted, it means the header wasn't
		// encrypted for us by this possible sender. Continue to the next possible sender.
		header, err := kem.Decrypt(buf[:0], pk.d, pk.q, pubS.q, header)
		if err != nil {
			continue
		}

		// If the header wss successfully decrypted, decode the DEK and message offset.
		dek := header[:internal.DEKSize]
		offset := binary.LittleEndian.Uint32(header[internal.DEKSize:])

		// Return the sender's public key, the DEK, and the offset.
		return pubS, dek, int(offset)
	}

	return nil, nil, 0
}

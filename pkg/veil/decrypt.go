package veil

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/authenc"
	"github.com/codahale/veil/pkg/veil/internal/authenc/streamio"
	"github.com/codahale/veil/pkg/veil/internal/kemkdf"
	"github.com/codahale/veil/pkg/veil/internal/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/schnorr/sigio"
	"github.com/gtank/ristretto255"
)

// Decrypt decrypts the data in src if originally encrypted by any of the given public keys. Returns
// the sender's public key, the number of decrypted bytes written, and the first reported error, if
// any.
//
// N.B.: Because Veil messages are streamed, it is possible that this may write some decrypted data
// to dst before it can discover that the ciphertext is invalid. If Decrypt returns an error, all
// output written to dst should be discarded, as it cannot be ascertained to be authentic.
func (pk *PrivateKey) Decrypt(dst io.Writer, src io.Reader, senders []*PublicKey) (*PublicKey, int64, error) {
	// Find a decryptable header and recover the ephemeral private key.
	headers, pkS, privEH, err := pk.findHeader(src, senders)
	if err != nil {
		return nil, 0, err
	}

	// Re-derive the ephemeral header public key.
	pubEH := ristretto255.NewElement().ScalarBaseMult(privEH)

	// Read the ephemeral message public key.
	buf := make([]byte, internal.ElementSize)
	if _, err := io.ReadFull(src, buf); err != nil {
		return nil, 0, err
	}

	// Decode the ephemeral message public key.
	pubEM := ristretto255.NewElement()
	if err := pubEM.Decode(buf); err != nil {
		return nil, 0, err
	}

	// Derive the shared ratchet key between the sender's public key and the ephemeral private key.
	key := kemkdf.Receive(privEH, pubEH, pkS.q, pubEM, authenc.KeySize, false)

	// Initialize an AEAD reader with the ratchet key, using the encrypted headers as authenticated
	// data.
	decryptor := streamio.NewReader(src, key, headers, streamio.BlockSize)

	// Detach the signature from the plaintext and pass the plaintext through a verifier.
	sr := sigio.NewReader(decryptor, schnorr.SignatureSize)
	verifier := schnorr.NewVerifier(sr)

	// Decrypt the plaintext as a stream.
	n, err := io.Copy(dst, verifier)
	if err != nil {
		return nil, n, err
	}

	// Verify the signature of the plaintext.
	if !verifier.Verify(pkS.q, sr.Signature) {
		return nil, n, ErrInvalidCiphertext
	}

	// Return the sender's public key and the number of bytes written.
	return pkS, n, nil
}

// findHeader scans src for header blocks encrypted by any of the given possible senders. Returns
// the full slice of encrypted headers, the sender's public key, and the ephemeral private key.
func (pk *PrivateKey) findHeader(
	src io.Reader, senders []*PublicKey,
) ([]byte, *PublicKey, *ristretto255.Scalar, error) {
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
		pkS, skEH, offset := pk.decryptHeader(buf, senders)

		// If we successfully decrypt the header, use the message offset to read the remaining
		// encrypted headers.
		if pkS != nil {
			remaining := make([]byte, offset-len(headers))
			if _, err := io.ReadFull(src, remaining); err != nil {
				return nil, nil, nil, err
			}

			// Return the full set of encrypted headers, the sender's public key, and the ephemeral
			// secret key.
			return append(headers, remaining...), pkS, skEH, nil
		}
	}
}

// decryptHeader attempts to decrypt the given header block if sent from any of the given public
// keys.
func (pk *PrivateKey) decryptHeader(buf []byte, senders []*PublicKey) (*PublicKey, *ristretto255.Scalar, int) {
	// Decode the possible public key.
	pubEH := ristretto255.NewElement()
	if err := pubEH.Decode(buf[:internal.ElementSize]); err != nil {
		return nil, nil, 0
	}

	// Extract the ciphertext.
	ciphertext := buf[internal.ElementSize:]

	// Iterate through all possible senders.
	for _, pubS := range senders {
		// Re-derive the shared key between the sender and recipient.
		key := kemkdf.Receive(pk.d, pk.q, pubS.q, pubEH, authenc.KeySize, true)

		// Try to decrypt the header. If the header cannot be decrypted, it means the header wasn't
		// encrypted for us by this possible sender. Continue to the next possible sender.
		header, err := authenc.DecryptHeader(key, pubEH, ciphertext, authenc.TagSize)
		if err != nil {
			continue
		}

		// If the header wss successfully decrypted, decode the ephemeral message private key and
		// message offset.
		privEM := ristretto255.NewScalar()
		if err := privEM.Decode(header[:internal.ScalarSize]); err != nil {
			continue
		}

		offset := binary.LittleEndian.Uint32(header[internal.ScalarSize:])

		// Return the sender's public key, the ephemeral private key, and the offset.
		return pubS, privEM, int(offset)
	}

	return nil, nil, 0
}

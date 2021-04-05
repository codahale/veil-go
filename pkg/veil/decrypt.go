package veil

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/codahale/veil/pkg/veil/internal/protocols/authenc"
	"github.com/codahale/veil/pkg/veil/internal/protocols/kemkdf"
	"github.com/codahale/veil/pkg/veil/internal/protocols/msghash"
	"github.com/codahale/veil/pkg/veil/internal/protocols/schnorr"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/codahale/veil/pkg/veil/internal/streamio"
	"github.com/gtank/ristretto255"
)

// ErrInvalidCiphertext is returned when a ciphertext cannot be decrypted, either due to an
// incorrect key or tampering.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

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
	buf := make([]byte, r255.PublicKeySize)
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
	r := streamio.NewReader(src, key, headers, blockSize)

	// Detach the signature from the plaintext and calculate a digest of the plaintext.
	h := msghash.NewWriter(digestSize)
	sr := streamio.NewSignatureReader(r, schnorr.SignatureSize)
	tr := io.TeeReader(sr, h)

	// Decrypt the plaintext as a stream.
	n, err := io.Copy(dst, tr)
	if err != nil {
		return nil, n, err
	}

	// Verify the signature of the digest.
	if !schnorr.Verify(pkS.q, sr.Signature, h.Digest()) {
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
	pubR := pk.PublicKey().q

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
		pkS, skEH, offset := pk.decryptHeader(pubR, buf, senders)

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
func (pk *PrivateKey) decryptHeader(
	pubR *ristretto255.Element, buf []byte, senders []*PublicKey,
) (*PublicKey, *ristretto255.Scalar, int) {
	// Decode the possible public key.
	pubEH := ristretto255.NewElement()
	if err := pubEH.Decode(buf[:r255.PublicKeySize]); err != nil {
		return nil, nil, 0
	}

	// Extract the ciphertext.
	ciphertext := buf[r255.PublicKeySize:]

	// Iterate through all possible senders.
	for _, pubS := range senders {
		// Re-derive the shared key between the sender and recipient.
		key := kemkdf.Receive(pk.d, pubR, pubS.q, pubEH, authenc.KeySize, true)

		// Try to decrypt the header. If the header cannot be decrypted, it means the header wasn't
		// encrypted for us by this possible sender. Continue to the next possible sender.
		header, err := authenc.DecryptHeader(key, pubEH, ciphertext, authenc.TagSize)
		if err != nil {
			continue
		}

		// If the header wss successfully decrypted, decode the ephemeral message private key and
		// message offset.
		privEM := ristretto255.NewScalar()
		if err := privEM.Decode(header[:r255.PrivateKeySize]); err != nil {
			continue
		}

		offset := binary.LittleEndian.Uint32(header[r255.PrivateKeySize:])

		// Return the sender's public key, the ephemeral private key, and the offset.
		return pubS, privEM, int(offset)
	}

	return nil, nil, 0
}

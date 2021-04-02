package veil

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/codahale/veil/internal/kem"
	"github.com/codahale/veil/internal/r255"
	"github.com/codahale/veil/internal/ratchet"
	"github.com/codahale/veil/internal/scopedhash"
	"github.com/codahale/veil/internal/stream"
	"github.com/codahale/veil/internal/sym"
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
func (sk *SecretKey) Decrypt(
	dst io.Writer, src io.Reader, senders []*PublicKey, derivationPath string,
) (*PublicKey, int64, error) {
	// Derive the recipient's private key.
	privR := sk.privateKey(derivationPath)

	// Find a decryptable header and recover the ephemeral private key.
	headers, pkS, privEH, err := sk.findHeader(src, privR, senders)
	if err != nil {
		return nil, 0, err
	}

	// Re-derive the ephemeral header public key.
	pubEH := privEH.PublicKey()

	// Read the ephemeral message public key.
	buf := make([]byte, r255.PublicKeySize)
	if _, err := io.ReadFull(src, buf); err != nil {
		return nil, 0, err
	}

	// Decode the ephemeral message public key.
	pubEM, err := r255.DecodePublicKey(buf)
	if err != nil {
		return nil, 0, err
	}

	// Derive the shared ratchet key between the sender's public key and the ephemeral private key.
	key := kem.Receive(privEH, pubEH, pkS.k, pubEM, scopedhash.NewMessageKDF, ratchet.KeySize)

	// Initialize an AEAD reader with the ratchet key, using the encrypted headers as authenticated
	// data.
	r := stream.NewReader(src, key, headers, blockSize)

	// Detach the signature from the plaintext and calculate a hash of it.
	h := scopedhash.NewMessageHash()
	sr := stream.NewSignatureReader(r, h, r255.SignatureSize)

	// Decrypt the plaintext as a stream.
	n, err := io.Copy(dst, sr)
	if err != nil {
		return nil, n, err
	}

	// Verify the signature of the plaintext.
	if !pkS.k.Verify(h.Sum(nil), sr.Signature) {
		return nil, n, ErrInvalidCiphertext
	}

	// Return the sender's public key and the number of bytes written.
	return pkS, n, nil
}

// findHeader scans src for header blocks encrypted by any of the given possible senders. Returns
// the full slice of encrypted headers, the sender's public key, and the ephemeral private key.
func (sk *SecretKey) findHeader(
	src io.Reader, privR *r255.PrivateKey, senders []*PublicKey,
) ([]byte, *PublicKey, *r255.PrivateKey, error) {
	headers := make([]byte, 0, len(senders)*encryptedHeaderSize) // a guess at initial capacity
	buf := make([]byte, encryptedHeaderSize)
	pubR := privR.PublicKey()

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
		pkS, skEH, offset := sk.decryptHeader(privR, pubR, buf, senders)

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
func (sk *SecretKey) decryptHeader(
	privR *r255.PrivateKey, pubR *r255.PublicKey, buf []byte, senders []*PublicKey,
) (*PublicKey, *r255.PrivateKey, int) {
	// Decode the possible public key.
	pubEH, err := r255.DecodePublicKey(buf[:r255.PublicKeySize])
	if err != nil {
		return nil, nil, 0
	}

	// Extract the ciphertext.
	ciphertext := buf[r255.PublicKeySize:]

	// Iterate through all possible senders.
	for _, pubS := range senders {
		// Re-derive the shared secret between the sender and recipient.
		secret := kem.Receive(privR, pubR, pubS.k, pubEH, scopedhash.NewHeaderKDF,
			sym.KeySize+sym.NonceSize)

		// Initialize an AEAD.
		aead, err := sym.NewAEAD(secret[:sym.KeySize])
		if err != nil {
			panic(err)
		}

		// Try to decrypt the header. If the header cannot be decrypted, it means the header wasn't
		// encrypted for us by this possible sender. Continue to the next possible sender.
		header, err := aead.Open(nil, secret[sym.KeySize:], ciphertext, nil)
		if err != nil {
			continue
		}

		// If the header wss successfully decrypted, decode the ephemeral message private key and
		// message offset.
		privEM, err := r255.DecodePrivateKey(header[:r255.PrivateKeySize])
		if err != nil {
			continue
		}

		offset := binary.BigEndian.Uint32(header[r255.PrivateKeySize:])

		// Return the sender's public key, the ephemeral private key, and the offset.
		return pubS, privEM, int(offset)
	}

	return nil, nil, 0
}

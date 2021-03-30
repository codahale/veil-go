package veil

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"

	"github.com/codahale/veil/internal/kem"
	"github.com/codahale/veil/internal/r255"
	"github.com/codahale/veil/internal/ratchet"
	"github.com/codahale/veil/internal/stream"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// ErrInvalidCiphertext is returned when a ciphertext cannot be decrypted, either due to an
// incorrect key or tampering.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

// Decrypt decrypts the data in src if originally encrypted by any of the given public keys. Returns
// the sender's public key, the number of decrypted bytes written, and the first reported error, if
// any.
// N.B.: Because Veil messages are streamed, it is possible that this may write some decrypted data
// to dst before it can discover that the ciphertext is invalid. If Decrypt returns an error, all
// output written to dst should be discarded, as it cannot be ascertained to be authentic.
func (sk *SecretKey) Decrypt(dst io.Writer, src io.Reader, senders []PublicKey) (PublicKey, int64, error) {
	// Find a decryptable header and recover the ephemeral secret key.
	headers, pkS, skEH, err := sk.findHeader(src, senders)
	if err != nil {
		return nil, 0, err
	}

	// Re-derive the ephemeral header public key.
	pkEH := r255.PublicKey(skEH)

	// Read the ephemeral message public key.
	pkEM := make([]byte, r255.PublicKeySize)
	if _, err := io.ReadFull(src, pkEM); err != nil {
		return nil, 0, err
	}

	// Derive the shared ratchet key between the sender and the ephemeral key.
	key := kem.Receive(skEH, pkEH, pkS, pkEM, []byte("message"), ratchet.KeySize)

	// Initialize an AEAD reader with the ratchet key, using the encrypted headers as authenticated
	// data.
	r := stream.NewReader(src, key, headers, blockSize)

	// Detach the signature from the plaintext and calculate a hash of it.
	h := sha512.New()
	sr := stream.NewSignatureReader(r, h, r255.SignatureSize)

	// Decrypt the plaintext as a stream.
	n, err := io.Copy(dst, sr)
	if err != nil {
		return nil, n, err
	}

	// Verify the signature of the plaintext.
	if !r255.Verify(pkS, h.Sum(nil), sr.Signature) {
		return nil, n, ErrInvalidCiphertext
	}

	// Return the sender's public key and the number of bytes written.
	return pkS, n, nil
}

// findHeader scans src for header blocks encrypted by any of the given possible senders. Returns
// the full slice of encrypted headers, the sender's public key, and the ephemeral secret key.
func (sk *SecretKey) findHeader(src io.Reader, senders []PublicKey) ([]byte, PublicKey, SecretKey, error) {
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
		pkEH := buf[:r255.PublicKeySize]
		ciphertext := buf[r255.PublicKeySize:]
		pkS, skEH, offset := sk.decryptHeader(pkEH, ciphertext, senders)

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
func (sk SecretKey) decryptHeader(pkEH, ciphertext []byte, senders []PublicKey) (PublicKey, SecretKey, int) {
	// Re-derive the recipient's public key.
	pk := sk.PublicKey()

	// Iterate through all possible senders.
	for _, pkS := range senders {
		// Re-derive the shared secret between the sender and recipient.
		secret := kem.Receive(sk, pk, pkS, pkEH, []byte("header"), chacha20.KeySize+chacha20.NonceSize)

		// Initialize a ChaCha20Poly1305 AEAD.
		aead, err := chacha20poly1305.New(secret[:chacha20.KeySize])
		if err != nil {
			panic(err)
		}

		// Try to decrypt the header. If the header cannot be decrypted, it means the header wasn't
		// encrypted for us by this possible sender. Continue to the next possible sender.
		header, err := aead.Open(nil, secret[chacha20.KeySize:], ciphertext, nil)
		if err != nil {
			continue
		}

		// If the header wss successful decrypted, decode the ephemeral message secret key and
		// message offset and return them.
		skEM := header[:r255.PublicKeySize]
		offset := binary.BigEndian.Uint32(header[r255.PublicKeySize:])

		return pkS, skEM, int(offset)
	}

	return nil, nil, 0
}

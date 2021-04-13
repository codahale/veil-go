// Package hpke provides the underlying STROBE protocol for Veil's hybrid public key encryption.
//
// Encrypting a message is as follows, given the sender's key pair, d_s and Q_s, a message in blocks
// M_0...M_n, a list of recipient public keys, Q_r0..Q_rm, a randomly generated data encryption
// key, K, and a tag size N:
//
//     INIT('veil.hpke', level=256)
//     AD(LE_32(N),      meta=true)
//     AD(Q_s)
//     KEY(K)
//     SEND_ENC('')
//     SEND_ENC(M_0,     more=true)
//     SEND_ENC(M_1,     more=true)
//     ...
//     SEND_ENC(M_n,     more=true)
//
// Having encrypted the plaintext, an authentication tag is generated but not written:
//
//     SEND_MAC(N) -> T
//
// Next, a header consisting of K, T, and LE_64(len(M)) is encapsulated for all recipient public
// keys using veil.kem. Random padding is prepended to the concatenated encrypted headers, and the
// block H is sent as cleartext:
//
//     SEND_CLR(H)
//
// Finally, an authentication tag is generated and written:
//
//     SEND_MAC(N)
//
// The resulting ciphertext then contains, in order:
//
// 1. The unauthenticated ciphertext of the message.
// 2. A block of encrypted headers (each containing a copy of the DEK, the message ciphertext tag,
//    and the message length) with random padding prepended.
// 3. An N-byte authentication tag.
//
// Decryption is as follows, given the recipient's key pair, d_r and Q_r, the sender's public key,
// Q_s, and a ciphertext in blocks C_0..C_n. First, the recipient seeks to the end of the ciphertext
// and then backwards by N bytes. Second, they seek backwards and read each possible encrypted
// header, attempting to decrypt it via veil.kem. Once they find a header which can be decrypted,
// they recover the DEK, the ciphertext MAC T, and the message offset. They they run the inverse of
// the encryption protocol:
//
//     INIT('veil.hpke', level=256)
//     AD(LE_32(N),      meta=true)
//     AD(Q_s)
//     KEY(K)
//     RECV_ENC('')
//     RECV_ENC(C_0,     more=true)
//     RECV_ENC(C_1,     more=true)
//     ...
//     RECV_ENC(C_n,     more=true)
//     RECV_MAC(T)
//     RECV_CLR(H)
//     RECV_MAC(N)
//
// This construction provides streaming, authenticated public key encryption with the following
// benefits:
//
// * Confidentiality and authenticity.
// * Forward secrecy for the sender.
// * Repudiability for the sender unless the recipient reveals their private key.
// * Encryption of arbitrarily-sized messages, provided ciphertexts can be seeked.
package hpke

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/kem"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/gtank/ristretto255"
)

// ErrInvalidCiphertext is returned when the ciphertext cannot be decrypted.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

// Encrypt reads the contents of src, encrypts them such that all members of qRs will be able to
// decrypt and authenticate them, and writes the encrypted contents to dst.
func Encrypt(
	dst io.Writer, src io.Reader, dS *ristretto255.Scalar, qS *ristretto255.Element,
	qRs []*ristretto255.Element, padding int,
) (int64, error) {
	// Generate a DEK.
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return 0, fmt.Errorf("error generating DEK: %w", err)
	}

	// Initialize the protocol.
	hpke := initProtocol(qS, dek)

	// Encrypt and send the plaintext.
	written, err := io.Copy(hpke.SendENCStream(dst), src)
	if err != nil {
		return written, err
	}

	// Send a MAC of the ciphertext.
	ctMac := hpke.SendMAC(nil, internal.TagSize)

	// Create a buffer for the header.
	header := make([]byte, headerSize)

	// Encode a header of the DEK, ciphertext MAC, and message length.
	copy(header, dek)
	copy(header[dekSize:], ctMac)
	binary.LittleEndian.PutUint64(header[dekSize+internal.TagSize:], uint64(written))

	// Create a buffer for the encrypted headers.
	headers := make([]byte, padding, padding+len(qRs)*encryptedHeaderSize)

	// Add random padding to the beginning of the headers.
	if _, err := rand.Read(headers); err != nil {
		return written, fmt.Errorf("error generating padding: %w", err)
	}

	// Encrypt copies of the header.
	for _, qR := range qRs {
		encHeader := kem.Encrypt(nil, dS, qS, qR, header)
		headers = append(headers, encHeader...)
	}

	// Send the encrypted headers. These will be mostly opaque to recipients, so we mark them as
	// cleartext in the protocol.
	hpke.SendCLR(headers)

	// Write the encrypted headers.
	n, err := dst.Write(headers)
	written += int64(n)

	if err != nil {
		return written, err
	}

	// Create and send a MAC.
	n, err = dst.Write(hpke.SendMAC(nil, internal.TagSize))
	written += int64(n)

	return written, err
}

// Decrypt reads the contents of src, decrypts them iff the owner of qS encrypted them for
// decryption by dR, and writes the decrypted contents to dst.
//nolint:gocognit,gocyclo,cyclop // This gets worse if split up into functions.
func Decrypt(dst io.Writer, src io.ReadSeeker, dR *ristretto255.Scalar, qR, qS *ristretto255.Element) (int64, error) {
	// Go to the very end of the ciphertext.
	offset, err := src.Seek(-internal.TagSize, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("error seeking in src: %w", err)
	}

	var (
		headerEnd  = offset
		dek, ctMac []byte
		messageEnd int64
		header     = make([]byte, encryptedHeaderSize)
	)

	for {
		// Back up a spot.
		offset -= encryptedHeaderSize
		if offset < 0 {
			// If we're at the beginning of the file, we're done looking.
			return 0, ErrInvalidCiphertext
		}

		// Seek to where the header might be.
		if _, err := src.Seek(offset, io.SeekStart); err != nil {
			return 0, fmt.Errorf("error seeking in src: %w", err)
		}

		// Read the possible header.
		if _, err := io.ReadFull(src, header); err != nil {
			return 0, fmt.Errorf("error reading header: %w", err)
		}

		// Try to decrypt the header.
		plaintext, err := kem.Decrypt(header[:0], dR, qR, qS, header)
		if err != nil {
			// If we can't, try the next possibility.
			continue
		}

		// Decode the DEK and the message length.
		dek = plaintext[:dekSize]
		ctMac = plaintext[dekSize : dekSize+internal.TagSize]
		messageEnd = int64(binary.LittleEndian.Uint64(plaintext[dekSize+internal.TagSize:]))

		// Go back the beginning of the input.
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return 0, fmt.Errorf("error seeking in src: %w", err)
		}

		break
	}

	// Initialize a new protocol.
	hpke := initProtocol(qS, dek)

	// Receive and decrypt the ciphertext.
	written, err := io.Copy(hpke.RecvENCStream(dst), io.LimitReader(src, messageEnd))
	if err != nil {
		return written, err
	}

	// Verify the MAC of the ciphertext with that recovered from the KEM.
	if err := hpke.RecvMAC(ctMac); err != nil {
		return written, ErrInvalidCiphertext
	}

	// Read the encrypted headers.
	headers := make([]byte, headerEnd-messageEnd)
	if _, err = io.ReadFull(src, headers); err != nil {
		return written, err
	}

	// Receive the encrypted headers.
	hpke.RecvCLR(headers)

	// Read the MAC of the ciphertext plus the headers.
	mac := make([]byte, internal.TagSize)
	if _, err = io.ReadFull(src, mac); err != nil {
		return written, err
	}

	// Validate the MAC.
	if err := hpke.RecvMAC(mac); err != nil {
		return written, ErrInvalidCiphertext
	}

	return written, nil
}

func initProtocol(qS *ristretto255.Element, dek []byte) *protocol.Protocol {
	// Initialize a new protocol.
	hpke := protocol.New("veil.hpke")

	// Add the tag size as associated metadata.
	hpke.MetaAD(protocol.LittleEndianU32(internal.TagSize))

	// Key the protocol with the DEK.
	hpke.KEY(dek)

	// Add the sender's public key as associated data.
	hpke.AD(qS.Encode(nil))

	return hpke
}

const (
	dekSize             = 64 // 512 bits for a hilarious margin of security in the multi-user model
	headerSize          = dekSize + internal.TagSize + 8
	encryptedHeaderSize = headerSize + kem.Overhead
)

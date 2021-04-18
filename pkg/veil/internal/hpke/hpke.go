// Package hpke provides the underlying STROBE protocol for Veil's hybrid public key encryption.
//
// Encrypting a message is as follows, given the sender's key pair, d_s and Q_s, a message in blocks
// M_0...M_n, a list of recipient public keys, Q_r0..Q_rm, a randomly generated data encryption
// key, K, a DEK size N_dek, and a tag size N_tag:
//
//     INIT('veil.hpke', level=256)
//     AD(LE_32(N_dek),  meta=true)
//     AD(LE_32(N_tag),  meta=true)
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
// Next, a footer consisting of K, T, and LE_64(len(M)) is encapsulated for all recipient public
// keys using veil.kem. Random padding is prepended to the concatenated encrypted footers, and the
// block F is sent as cleartext:
//
//     SEND_CLR(F)
//
// Finally, a veil.schnorr signature S of the encrypted footers F is encrypted and sent:
//
//     SEND_ENC(S)
//
// The resulting ciphertext then contains, in order:
//
// 1. The unauthenticated ciphertext of the message.
// 2. A block of encrypted footers (each containing a copy of the DEK, the message ciphertext tag,
//    and the message length) with random padding prepended.
// 3. An encrypted signature of the encrypted footers.
//
// Decryption is as follows, given the recipient's key pair, d_r and Q_r, the sender's public key,
// Q_s, and a ciphertext in blocks C_0..C_n. First, the recipient seeks to the end of the ciphertext
// and then backwards by N bytes. Second, they seek backwards and read each possible encrypted
// footer, attempting to decrypt it via veil.kem. Once they find a footer which can be decrypted,
// they recover the DEK, the ciphertext MAC T, and the message offset. They they run the inverse of
// the encryption protocol:
//
//     INIT('veil.hpke', level=256)
//     AD(LE_32(N_dek),  meta=true)
//     AD(LE_32(N_tag),  meta=true)
//     AD(Q_s)
//     KEY(K)
//     RECV_ENC('')
//     RECV_ENC(C_0,     more=true)
//     RECV_ENC(C_1,     more=true)
//     ...
//     RECV_ENC(C_n,     more=true)
//     RECV_MAC(T)
//     RECV_CLR(F)
//     RECV_ENC(S)
//
// Finally, the signature S is verified against the received footers F.
//
// This construction provides streaming, authenticated public key encryption with the following
// benefits:
//
// * Confidentiality and authenticity.
// * Forward secrecy for the sender.
// * Repudiability for the sender unless a recipient reveals their private key.
// * Encryption of arbitrarily-sized messages, provided ciphertexts can be seeked.
//
// Borrowing Alwen et. al's analysis of the proposed HPKE specification, this construction is
// intended to provide privacy and authenticity under both outsider and insider attacks. For a
// single recipient, the construction is similar to the proposed HPKE specification, if the
// authentication tag were sent in the clear as part of a traditional EtM AEAD design, and thus can
// be assumed to have similar privacy properties for outsider and insider attacks. Similarly,
// they show outsider authenticity to depend on the AKEM's Outsider-CCA/Outsider-Auth properties
// combined with the AEAD's IND-CTXT property, which veil.hpke also provides.
//
// In contrast to the proposed HPKE specification, veil.hpke protects against the DEM-reuse attack
// Alwen et. al detail in Section 5.4:
//
//     We can show that for any AKEM, KS, and AEAD, the construction APKE[AKEM,KS, AEAD] given in
//     Listing 8 is not (n,qe,qd)-Insider-Auth secure. The inherent reason for this construction to
//     be vulnerable against this attack is that the KEM ciphertext does not depend on the message.
//     Thus, the KEM ciphertext can be reused and the DEM ciphertext can be exchanged by the
//     encryption of any other message.
//
// Veil's lack of framing data means that recipients don't know the actual ciphertext before they
// begin attempting to decrypt footers, so an existing construction like Tag-AKEM can't be used.
// veil.hpke takes advantage of the fact that veil.kem is not a traditional KEM construction (i.e.,
// it's actually a miniature AKEM/AEAD itself) to make the KEM ciphertexts dependent on the DEM
// ciphertext by including a MAC of the DEM ciphertext along with the DEK as plaintext for veil.kem.
// An insider attempting to re-use the KEM ciphertext with a forged DEM ciphertext will be foiled by
// recipients checking the recovered MAC from the KEM ciphertext against the ersatz DEM ciphertext.
//
// The remaining piece of veil.hpke ciphertext to protect are the KEM footers for other recipients.
// The signature of the encrypted footers assures their authenticity, the authenticity of the
// DEK/MAC, and thus the authenticity of the message, but cannot be verified without the DEK, or
// even distinguished from random noise.
//
// Further, if the DEK is revealed, third parties will be able to decrypt the message and verify the
// signature, but cannot confirm that the encrypted footers contain the DEK or that the message is
// from the sender, only that the sender created a message with those encrypted footers.
//
// See https://eprint.iacr.org/2020/1499.pdf
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
	"github.com/codahale/veil/pkg/veil/internal/schnorr"
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
	// Create a buffer for the footer.
	footer := make([]byte, footerSize)

	// Generate a DEK at the start of the footer.
	dek := footer[:dekSize]
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

	// Send a MAC of the ciphertext and add it to the middle of the footer.
	hpke.SendMAC(footer[:dekSize], internal.TagSize)

	// Add the message length to the end of the footer.
	binary.LittleEndian.PutUint64(footer[dekSize+internal.TagSize:], uint64(written))

	// Create a buffer for the encrypted footers.
	footers := make([]byte, padding, padding+len(qRs)*encryptedFooterSize)

	// Add random padding to the beginning of the encrypted footers.
	if _, err := rand.Read(footers); err != nil {
		return written, fmt.Errorf("error generating padding: %w", err)
	}

	// Encrypt copies of the footer.
	for _, qR := range qRs {
		footers = kem.Encrypt(footers, dS, qS, qR, footer)
	}

	// Send the encrypted footers. These will be mostly opaque to recipients, so we mark them as
	// cleartext in the protocol.
	hpke.SendCLR(footers)

	// Write the encrypted footers.
	n, err := dst.Write(footers)
	written += int64(n)

	if err != nil {
		return written, err
	}

	// Create a signature of the footers.
	signer := schnorr.NewSigner(dS, qS)
	_, _ = signer.Write(footers)

	sig, err := signer.Sign()
	if err != nil {
		return written, err
	}

	// Encrypt and send the signature.
	sig = hpke.SendENC(sig[:0], sig)

	// Write the signature.
	n, err = dst.Write(sig)
	written += int64(n)

	return written, err
}

// Decrypt reads the contents of src, decrypts them iff the owner of qS encrypted them for
// decryption by dR, and writes the decrypted contents to dst.
//nolint:gocognit,gocyclo,cyclop // This gets worse if split up into functions.
func Decrypt(dst io.Writer, src io.ReadSeeker, dR *ristretto255.Scalar, qR, qS *ristretto255.Element) (int64, error) {
	// Go to the very end of the ciphertext.
	offset, err := src.Seek(-schnorr.SignatureSize, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("error seeking in src: %w", err)
	}

	var (
		footerEnd  = offset
		dek, ctMac []byte
		messageEnd int64
		footer     = make([]byte, encryptedFooterSize)
	)

	for {
		// Back up a spot.
		offset -= encryptedFooterSize
		if offset < 0 {
			// If we're at the beginning of the file, we're done looking.
			return 0, ErrInvalidCiphertext
		}

		// Seek to where the footer might be.
		if _, err := src.Seek(offset, io.SeekStart); err != nil {
			return 0, fmt.Errorf("error seeking in src: %w", err)
		}

		// Read the possible footer.
		if _, err := io.ReadFull(src, footer); err != nil {
			return 0, fmt.Errorf("error reading footer: %w", err)
		}

		// Try to decrypt the footer.
		plaintext, err := kem.Decrypt(footer[:0], dR, qR, qS, footer)
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

	// Read the encrypted footers.
	footers := make([]byte, footerEnd-messageEnd)
	if _, err = io.ReadFull(src, footers); err != nil {
		return written, err
	}

	// Receive the encrypted footers.
	hpke.RecvCLR(footers)

	// Read the signature of the encrypted footers.
	sig := make([]byte, schnorr.SignatureSize)
	if _, err = io.ReadFull(src, sig); err != nil {
		return written, err
	}

	// Decrypt the signature.
	sig = hpke.RecvENC(sig[:0], sig)

	// Verify the signature.
	verifier := schnorr.NewVerifier(qS)
	_, _ = verifier.Write(footers)

	if !verifier.Verify(sig) {
		return written, ErrInvalidCiphertext
	}

	return written, nil
}

func initProtocol(qS *ristretto255.Element, dek []byte) *protocol.Protocol {
	// Initialize a new protocol.
	hpke := protocol.New("veil.hpke")

	// Add the DEK size as associated metadata.
	hpke.MetaAD(protocol.LittleEndianU32(dekSize))

	// Add the tag size as associated metadata.
	hpke.MetaAD(protocol.LittleEndianU32(internal.TagSize))

	// Key the protocol with the DEK.
	hpke.KEY(dek)

	// Add the sender's public key as associated data.
	hpke.AD(qS.Encode(nil))

	return hpke
}

const (
	dekSize             = 32
	footerSize          = dekSize + internal.TagSize + 8
	encryptedFooterSize = footerSize + kem.Overhead
)

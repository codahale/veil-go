// Package mres provides the underlying STROBE protocol for Veil's multi-recipient encryption
// system.
//
// Encryption
//
// Encrypting a message is as follows, given the sender's key pair, d_s and Q_s, a message in blocks
// M_0...M_n, a list of recipient public keys, Q_r0..Q_rm, a randomly generated data encryption
// key, K, a DEK size N_dek, and a tag size N_tag:
//
//     INIT('veil.mres', level=256)
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
// Next, footers consisting of K, T, and LE_64(len(M)) are encrypted for all recipient public keys
// using veil.hpke. Random padding is prepended to the concatenated encrypted footers, and the block
// F is sent as cleartext:
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
// 2. A block of encrypted footers (each containing a copy of the DEK, an authentication tag of the
//    message ciphertext and the message length) with random padding prepended.
// 3. An encrypted signature of the encrypted footers.
//
// Decryption
//
// Decryption is as follows, given the recipient's key pair, d_r and Q_r, the sender's public key,
// Q_s, and a ciphertext C: the recipient seeks to the end of the encrypted footers (64 bytes from
// the end of C), then seeks backwards by the length of an encrypted footer, reading each encrypted
// footer and attempting to decrypt it via veil.hpke.
//
// Once they find a footer which can be decrypted, they recover the DEK, the ciphertext
// authentication tag T, and the message offset. They then seek to the beginning of C and run the
// inverse of the encryption protocol:
//
//     INIT('veil.mres', level=256)
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
// Insider And Outsider Privacy
//
// Borrowing An et al.'s notions of outsider and insider security
// (https://www.iacr.org/archive/eurocrypt2002/23320080/adr.pdf), this construction is intended to
// provide both privacy under both outsider and insider attacks. For a single recipient, the
// construction is similar to the proposed HPKE specification
// (https://tools.ietf.org/html/draft-irtf-cfrg-hpke-08), if the authentication tag were sent in the
// clear as part of a traditional EtM AEAD design, and thus can be assumed to have similar privacy
// properties for outsider and insider attacks (see Alwen et al.,
// https://eprint.iacr.org/2020/1499.pdf and Lipp https://eprint.iacr.org/2020/243.pdf).
//
// Outsider Authenticity
//
// Per prior analysis of the proposed HPKE specification, veil.mres should be security against
// outsider forgery attacks. Creating valid footers without the sender's private key would imply
// veil.hpke is not IND-CCA2 secure, and creating valid message ciphertexts and MACs without the DEK
// would imply STROBE is not IND-CCA2 secure (https://eprint.iacr.org/2017/003.pdf, section 5.1).
//
// Insider Authenticity
//
// In contrast to most HPKE constructions, veil.mres provides insider authenticity against the
// DEM-reuse attack Alwen et. al detail in Section 5.4:
//
//     We can show that for any AKEM, KS, and AEAD, the construction APKE[AKEM,KS, AEAD] given in
//     Listing 8 is not (n,qe,qd)-Insider-Auth secure. The inherent reason for this construction to
//     be vulnerable against this attack is that the KEM ciphertext does not depend on the message.
//     Thus, the KEM ciphertext can be reused and the DEM ciphertext can be exchanged by the
//     encryption of any other message.
//
// Veil's lack of framing data means that recipients don't know the actual ciphertext before they
// begin attempting to decrypt footers, so an existing construction like Tag-AKEM (see
// https://eprint.iacr.org/2005/027.pdf) can't be used. Instead, veil.mres includes a MAC of the DEM
// ciphertext along with the DEK as plaintext for veil.hpke, thereby making the KEM ciphertexts
// dependent on the message. An insider attempting to re-use the encrypted footers with a forged DEM
// ciphertext will be foiled by recipients checking the recovered MAC from the footer against the
// ersatz DEM ciphertext.
//
// The remaining piece of veil.mres ciphertext to protect is the set of footers which are encrypted
// for other recipients. The signature of the encrypted footers assures their authenticity, the
// authenticity of the DEK/MAC, and thus the authenticity of the message, but cannot be verified
// without the DEK, or even distinguished from random noise.
//
// In terms of logical dependencies, the DEM ciphertext depends on the message and the DEK, the
// footer ciphertexts depend on the DEK and the DEM ciphertext, and the final signature depends on
// the DEK and the footer ciphertexts.
//
// Repudiability
//
// If the DEK is revealed, third parties will be able to decrypt the message and verify the
// signature, but cannot confirm that the encrypted footers contain the DEK or that the message is
// from the sender, only that the sender created a message with those encrypted footers.
// Technically, this is a looser guarantee of repudiability, but practically the sender is only
// unable to repudiate a set of IND-CCA2 secure ciphertexts.
package mres

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/hpke"
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
	mres := initProtocol(qS, dek)

	// Encrypt and send the plaintext.
	written, err := io.Copy(mres.SendENCStream(dst), src)
	if err != nil {
		return written, err
	}

	// Send a MAC of the ciphertext and add it to the middle of the footer.
	mres.SendMAC(footer[:dekSize])

	// Add the message length to the end of the footer.
	binary.LittleEndian.PutUint64(footer[dekSize+internal.TagSize:], uint64(written))

	// Create a new signer for the encrypted footers.
	signer := schnorr.NewSigner(dS, qS)
	sdst := io.MultiWriter(signer, mres.SendCLRStream(dst))

	// Add random padding to the beginning of the encrypted footers.
	pn, err := io.CopyN(sdst, rand.Reader, int64(padding))
	written += pn

	if err != nil {
		return written, err
	}

	// Create a buffer for the encrypted footers.
	encFooter := make([]byte, len(footer)+hpke.Overhead)

	// Encrypt, sign, and writes copies of the footer.
	for _, qR := range qRs {
		encFooter, err = hpke.Encrypt(encFooter[:0], dS, qS, qR, footer)
		if err != nil {
			return written, err
		}

		n, err := sdst.Write(encFooter)
		written += int64(n)

		if err != nil {
			return written, err
		}
	}

	// Create a signature of the footers.
	sig, err := signer.Sign()
	if err != nil {
		return written, err
	}

	// Encrypt and send the signature.
	sig = mres.SendENC(sig[:0], sig)

	// Write the signature.
	n, err := dst.Write(sig)
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
		plaintext, err := hpke.Decrypt(footer[:0], dR, qR, qS, footer)
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
	mres := initProtocol(qS, dek)

	// Receive and decrypt the ciphertext.
	written, err := io.Copy(mres.RecvENCStream(dst), io.LimitReader(src, messageEnd))
	if err != nil {
		return written, err
	}

	// Verify the MAC of the ciphertext with that recovered from the footer.
	if err := mres.RecvMAC(ctMac); err != nil {
		return written, ErrInvalidCiphertext
	}

	// Create a verifier for the encrypted footers.
	verifier := schnorr.NewVerifier(qS)
	vdst := mres.RecvCLRStream(verifier)

	// Read the encrypted footers, adding them to the verifier and the protocol.
	if _, err := io.CopyN(vdst, src, footerEnd-messageEnd); err != nil {
		return written, err
	}

	// Read the signature of the encrypted footers.
	sig := make([]byte, schnorr.SignatureSize)
	if _, err = io.ReadFull(src, sig); err != nil {
		return written, err
	}

	// Decrypt the signature.
	sig = mres.RecvENC(sig[:0], sig)

	// Verify the signature of the encrypted footers.
	if !verifier.Verify(sig) {
		return written, ErrInvalidCiphertext
	}

	return written, nil
}

func initProtocol(qS *ristretto255.Element, dek []byte) *protocol.Protocol {
	// Initialize a new protocol.
	mres := protocol.New("veil.mres")

	// Add the DEK size as associated metadata.
	mres.MetaAD(protocol.LittleEndianU32(dekSize))

	// Add the tag size as associated metadata.
	mres.MetaAD(protocol.LittleEndianU32(internal.TagSize))

	// Key the protocol with the DEK.
	mres.KEY(dek)

	// Add the sender's public key as associated data.
	mres.AD(qS.Encode(nil))

	return mres
}

const (
	dekSize             = 32
	footerSize          = dekSize + internal.TagSize + 8
	encryptedFooterSize = footerSize + hpke.Overhead
)

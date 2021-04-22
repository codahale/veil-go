// Package mres provides the underlying STROBE protocol for Veil's multi-recipient encryption
// system.
//
// Encryption
//
// Encrypting a message is as follows, given the sender's key pair, d_s and Q_s, a message in blocks
// M_0…M_n, a list of recipient public keys, Q_r0..Q_rm, a randomly generated data encryption key,
// K, a DEK size N_dek, and a MAC size N_mac:
//
//  INIT('veil.mres', level=256)
//  AD(LE_32(N_dek),  meta=true)
//  AD(LE_32(N_mac),  meta=true)
//  AD(Q_s)
//  KEY(K)
//  SEND_ENC('')
//  SEND_ENC(M_0,     more=true)
//  SEND_ENC(M_1,     more=true)
//  …
//  SEND_ENC(M_n,     more=true)
//
// Having encrypted the plaintext, a MAC is generated but not written:
//
//  SEND_MAC(N) -> T
//
// Next, footers consisting of T, K, and LE_64(len(M)) are encrypted for all recipient public keys
// using veil.hpke. Random padding is prepended to the concatenated encrypted footers, and the block
// F is sent as cleartext:
//
//  SEND_CLR(F)
//
// Finally, a veil.schnorr signature S of the encrypted footers F is encrypted and sent:
//
//  SEND_ENC(S)
//
// The resulting ciphertext then contains, in order: the unauthenticated ciphertext of the message;
// a block of encrypted footers (each containing a copy of the DEK, a MAC of the message ciphertext
// and the message length) with random padding prepended; an encrypted signature of the encrypted
// footers.
//
// Decryption
//
// Decryption is as follows, given the recipient's key pair, d_r and Q_r, the sender's public key,
// Q_s, and a ciphertext C: the recipient seeks to the end of the encrypted footers (64 bytes from
// the end of C), then seeks backwards by the length of an encrypted footer, reading each encrypted
// footer and attempting to decrypt it via veil.hpke.
//
// Once they find a footer which can be decrypted, they recover the ciphertext MAC T, the DEK, and
// the message offset. They then seek to the beginning of C and run the inverse of the encryption
// protocol:
//
//  INIT('veil.mres', level=256)
//  AD(LE_32(N_dek),  meta=true)
//  AD(LE_32(N_mac),  meta=true)
//  AD(Q_s)
//  KEY(K)
//  RECV_ENC('')
//  RECV_ENC(C_0,     more=true)
//  RECV_ENC(C_1,     more=true)
//  …
//  RECV_ENC(C_n,     more=true)
//  RECV_MAC(T)
//  RECV_CLR(F)
//  RECV_ENC(S)
//
// Finally, the signature S is verified against the received footers F.
//
// Multi-User Security
//
// In analyzing signcryption in the multi-user setting, Badertscher et al. lay out an informal set
// of desired behavior for multi-user signcryption (https://eprint.iacr.org/2018/050.pdf):
//
//  1. If two uncompromised legitimate users communicate, then the secure network guarantees that
//     the network attacker learns at most the length of the messages and the attacker cannot inject
//     any message into this communication: the communication between them can be called secure.
//  2. If, however, the legitimate sender is compromised, but not the receiver, then the network
//     allows the attacker to inject messages in the name of this sender. Still, Eve does not learn
//     the contents of the messages to the receiver: the communication is thus only confidential.
//  3. If, on the other hand, the legitimate receiver is compromised, but not the sender, the secure
//     network allows Eve to read the contents of the messages sent to this compromised user. Still,
//     no messages can be injected into this communication: the communication is only authentic.
//  4. If both, sender and receiver, are compromised, then the network does not give any guarantee
//     on their communication, Eve can read every message and inject anything at will.
//
// They factor this into two formal notions of security to capture these four criteria: multi-user
// outsider security and multi-user insider security, which effectively capture the IND-CCA2 and
// SUF-CMA security notions in their respective contexts.
//
// Multi-User Outsider Security
//
// In the single-recipient setting, this construction is equivalent to Construction 12.10 of Modern
// Cryptography 3e. Per Theorem 12.14, it is CCA-secure if the KEM and underlying private-key
// encryption system are CCA-secure. As veil.hpke is CCA-secure, it can be inferred that veil.mres
// is CCA-secure in the single-recipient setting.
//
// For attackers not included in the list of message recipients, veil.mres is strongly unforgeable
// under chosen message attack. veil.schnorr is SUF-CMA over the encrypted footers, which contain a
// MAC of the ciphertext, making it equivalent to Construction 13.3 of Modern Cryptography 3e. Per
// Theorem 13.4, its security is that of the underlying hash function's collision resistance, which
// for STROBE is very high.
//
// From this we can informally infer that veil.mres is outsider-secure in the multi-user setting,
// meeting the first criterion.
//
// Multi-User Insider Security
//
// Badertscher et al.'s notion of multi-user insider security combines FSO/FUO-IND-CCA2 security
// with FSO/FUO-SUF-CMA security, as captured by the second and third criteria.
//
// In the event of a compromised sender, veil.hpke's sender forward security prevents a passive
// adversary from learning the contents of a message without additional collusion (e.g. leaking the
// DEK, or adding themselves as a recipient).
//
// In the event of a compromised sender, veil.schnorr's strong unforgeability prevents an active
// attacker from injecting forged encrypted footers into the network. Because the encrypted footers
// contain a MAC of the message ciphertext, this implies that an active attacker would be unable to
// inject a forged message.
//
// As a result (and in contrast to most constructions), veil.mres protects against the DEM-reuse
// attack Alwen et al. (https://eprint.iacr.org/2020/1499.pdf) detail against the proposed HPKE
// standard:
//
//  We can show that for any AKEM, KS, and AEAD, the construction APKE[AKEM,KS, AEAD] given in
//  Listing 8 is not (n,qe,qd)-Insider-Auth secure. The inherent reason for this construction to be
//  vulnerable against this attack is that the KEM ciphertext does not depend on the message. Thus,
//  the KEM ciphertext can be reused and the DEM ciphertext can be exchanged by the encryption of
//  any other message.
//
// In order to make the KEM ciphertext entirely dependent on the message, veil.mres begins each
// footer plaintext with the MAC of the DEM ciphertext along with the DEK and the length of the
// message. These three components are modeled as distinct STROBE operations within veil.hpke,
// making the encryption of the DEK and the message length cryptographically dependent on the MAC.
//
// This construction can be considered a variant of Abe et al.'s Tag-KEM
// (https://www.shoup.net/papers/tagkemdem.pdf), where the tag (τ) is recovered from the KEM
// ciphertext and compared post-hoc instead of being calculated pre-hoc and passed as an argument.
// (This is analogous to AES-SIV comparing the resulting plaintext on decryption to the synthetic IV
// vs. AES-GCM comparing the received MAC to a re-calculated MAC of the received ciphertext.)
//
// Consequently, an insider attempting to re-use the encrypted footers with a forged DEM ciphertext
// will be foiled by recipients checking the recovered MAC from the footer against the ersatz DEM
// ciphertext. Because the signature covers the entirety of the footers, including padding, any
// recipient will be able to detect any ciphertext manipulations, making it strongly non-malleable
// in the multi-user setting.
//
// Encrypt-Then-Sign Security and Repudiability
//
// veil.schnorr is a strong signature scheme, veil.mres is CCA-secure, and both protocols strongly
// bind sender identity. These meet the criteria for an encrypt-then-sign construction to be secure.
//
// The signature of the encrypted footers assures their authenticity, the authenticity of the
// DEK/MAC, and thus the authenticity of the message, but cannot be verified without the DEK, or
// even distinguished from random noise.
//
// If the DEK is revealed, third parties will be able to decrypt the message and verify the
// signature, but cannot confirm that the encrypted footers contain the DEK or that the message is
// from the sender, only that the sender created a message with those encrypted footers.
// Technically, this is a looser guarantee of repudiability, but practically the sender is only
// unable to repudiate a set of IND-CCA2 secure ciphertexts. Unlike the Sign-then-Encrypt
// construction, a recipient is unable to present a decrypted, signed message to third parties.
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
	buf := make([]byte, footerSize)
	mac := buf[:internal.MACSize]
	dek := buf[internal.MACSize : internal.MACSize+dekSize]
	msgSize := buf[internal.MACSize+dekSize:]

	// Generate a DEK.
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

	// Create a MAC of the ciphertext.
	mac = mres.SendMAC(mac[:0])

	// Encode the message length as a 64-bit little endian integer.
	binary.LittleEndian.PutUint64(msgSize, uint64(written))

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
	footer := [][]byte{mac, dek, msgSize}
	encFooter := make([]byte, footerSize+hpke.Overhead)

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
		encFooter  = make([]byte, encryptedFooterSize)
		footerBuf  = make([]byte, footerSize)
		footer     = [][]byte{
			footerBuf[:internal.MACSize][:0],
			footerBuf[internal.MACSize : internal.MACSize+dekSize][:0],
			footerBuf[internal.MACSize+dekSize:][:0],
		}
		sizes = []int{internal.MACSize, dekSize, 8}
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
		if _, err := io.ReadFull(src, encFooter); err != nil {
			return 0, fmt.Errorf("error reading footer: %w", err)
		}

		// Try to decrypt the footer.
		plaintext, err := hpke.Decrypt(footer, dR, qR, qS, encFooter, sizes)
		if err != nil {
			// If we can't, try the next possibility.
			continue
		}

		// Unpack the footer contents.
		ctMac = plaintext[0]
		dek = plaintext[1]
		messageEnd = int64(binary.LittleEndian.Uint64(plaintext[2]))

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

	// Add the MAC size as associated metadata.
	mres.MetaAD(protocol.LittleEndianU32(internal.MACSize))

	// Key the protocol with the DEK.
	mres.KEY(dek)

	// Add the sender's public key as associated data.
	mres.AD(qS.Encode(nil))

	return mres
}

const (
	dekSize             = 32
	footerSize          = dekSize + internal.MACSize + 8
	encryptedFooterSize = footerSize + hpke.Overhead
)

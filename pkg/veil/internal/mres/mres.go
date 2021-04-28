// Package mres provides the underlying STROBE protocol for Veil's multi-recipient encryption
// system.
//
// Encryption
//
// Encrypting a message begins as follows, given the sender's key pair, d_s and Q_s, a plaintext
// message in blocks P_0…P_n, a list of recipient public keys, Q_r0..Q_rm, and a DEK size N_dek:
//
//  INIT('veil.mres', level=256)
//  AD(LE_32(N_dek),  meta=true)
//  AD(Q_s)
//
// The protocol context is cloned and keyed with the sender's private key and a random nonce and used
// to derive a data encryption key, K_dek, and an ephemeral private key, d_e:
//
//  KEY(d_s)
//  KEY(96)
//  PRF(32) -> K_dek
//  PRF(64) -> d_e
//
// The ephemeral public key is computed and the cloned context is discarded:
//
//  Q_e = G^d_e
//
// The data encryption key and the message offset are encoded into a fixed-length header and copies
// of it are encrypted with veil.hpke for each recipient using d_e and Q_e. Optional random padding
// is added to the end, and the resulting block H is written:
//
//  SEND_CLR(H)
//
// The protocol is keyed with the DEK and the encrypted message is written:
//
//  KEY(K_dek)
//  SEND_ENC('')
//  SEND_ENC(P_0,     more=true)
//  …
//  SEND_ENC(P_n,     more=true)
//
// Finally, a Schnorr signature S of the entire ciphertext (headers, padding, and DEM ciphertext) is
// created with d_e and encrypted:
//
//  SEND_ENC(S)
//
// The resulting ciphertext then contains, in order: the veil.hpke-encrypted headers, random
// padding, message ciphertext, and a Schnorr signature of the headers, padding, and ciphertext.
//
// Decryption
//
// Decryption begins as follows, given the recipient's key pair, d_r and Q_r, the sender's public
// key, Q_s:
//
//  INIT('veil.mres', level=256)
//  AD(LE_32(N_dek),  meta=true)
//  AD(Q_s)
//
// The recipient reads through the ciphertext in header-sized blocks, looking for one which is
// decryptable given their key pair and the sender's public key. Having found one, they recover the
// data encryption key K_dek, the message offset, and the ephemeral public key Q_e.
// They then read the remainder of the block of encrypted headers and padding H:
//
//  RECV_CLR(H)
//
// The protocol is keyed with the DEK and the plaintext decrypted:
//
//  KEY(K_dek)
//  RECV_ENC('')
//  RECV_ENC(C_0,     more=true)
//  …
//  RECV_ENC(C_n,     more=true)
//
// Finally, the signature S is decrypted and verified against the entire ciphertext:
//
//  RECV_ENC(S)
//
// Multi-Recipient Confidentiality
//
// To evaluate the confidentiality of this construction, consider an attacker provided with an
// encryption oracle for the sender's private key and a decryption oracle for each recipient,
// engaged in an IND-CCA2 game with the goal of gaining an advantage against any individual
// recipient. The elements they have to analyze and manipulate are the encrypted headers, the random
// padding, the message ciphertext, and the signature.
//
// Each recipient's header is an IND-CCA2-secure ciphertext, so an attacker can gain no advantage
// there. Further, the attacker cannot modify the copy of the DEK, the ephemeral public key, or the
// header length each recipient receives.
//
// The encrypted headers and/or padding for other recipients are not IND-CCA2-secure for all
// recipients, so the attacker may modify those without producing invalid headers. Similarly, the
// encrypted message is only IND-CPA-secure. Any attacker attempting to modify any of those,
// however, will have to forge a valid signature for the overall message to be valid. As
// veil.schnorr is SUF-CMA-secure, this is not possible.
//
// Multi-Recipient Authenticity
//
// Similarly, an attacker engaged in parallel CMA games with recipients has negligible advantage in
// forging messages. The veil.schnorr signature covers the entirety of the ciphertext.
//
// The standard KEM/DEM hybrid construction (i.e. Construction 12.20 from Modern Cryptography 3e)
// provides strong confidentiality (per Theorem 12.14), but no authenticity. A compromised recipient
// can replace the DEM component of the ciphertext with an arbitrary message encrypted with the same
// DEK. Even if the KEM provides strong authenticity against insider attacks, the KEM/DEM
// construction does not. Alwen et al. (https://eprint.iacr.org/2020/1499.pdf) detail this attack
// against the proposed HPKE standard.
//
// In the single-recipient setting, the practical advantages of this attack are limited: the
// attacker can forge messages which appear to be from a sender but are only decryptable by the
// attacker. In the multi-recipient setting, however, the practical advantage is much greater: the
// attacker can present forged messages which appear to be from a sender to other, honest
// recipients.
//
// veil.mres eliminates this attack by using the ephemeral key pair to sign the entire ciphertext
// and including only the public key in the KEM ciphertext. Re-using the KEM ciphertexts with a new
// message requires forging a new signature for a SUF-CMA-secure scheme. The use of an authenticated
// KEM serves to authenticate the ephemeral public key and thus the message: only the possessor of
// the sender's private key can calculate the static shared secret used to encrypt the ephemeral
// public key, and the recipient can only forge KEM ciphertexts with themselves as the intended
// recipient.
//
// Repudiability
//
// Because the sender's private key is only used to calculate shared secrets, a veil.mres ciphertext
// is entirely repudiable unless a recipient reveals their public key. The veil.schnorr keys are
// randomly generated for each message and all other forms of sender identity which are transmitted
// are only binding on public information.
//
// Randomness Re-Use
//
// The ephemeral key pair, d_e and Q_e, are used multiple times: once for each veil.hpke header and
// finally once for the end signature. This improves the efficiency of the scheme without reducing
// its security, per Bellare et al.'s treatment of Randomness Reusing Multi-Recipient Encryption
// Schemes (http://cseweb.ucsd.edu/~Mihir/papers/bbs.pdf).
//
// Ephemeral Scalar Hedging
//
// In deriving the DEK and ephemeral scalar from a cloned context, veil.mres uses Aranha et al.'s "hedged
// signature" technique (https://eprint.iacr.org/2019/956.pdf) to mitigate against both catastrophic
// randomness failures and differential fault attacks against purely deterministic signature
// schemes.
//
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
	"github.com/codahale/veil/pkg/veil/internal/schnorr/sigio"
	"github.com/gtank/ristretto255"
)

// Encrypt reads the contents of src, encrypts them such that all members of qRs will be able to
// decrypt and authenticate them, and writes the encrypted contents to dst.
func Encrypt(
	dst io.Writer, src io.Reader, dS *ristretto255.Scalar, qS *ristretto255.Element,
	qRs []*ristretto255.Element, padding int,
) (written int64, err error) {
	// Initialize the protocol.
	mres := initProtocol(qS)

	// Clone the protocol.
	clone := mres.Clone()

	// Key the clone with the sender's private key.
	clone.KEY(dS.Encode(nil))

	// Key the clone with a random key.
	if err := clone.KEYRand(dekSize + internal.UniformBytestringSize); err != nil {
		return 0, fmt.Errorf("error generating random value: %w", err)
	}

	// Generate a DEK with the clone.
	dek := clone.PRF(nil, dekSize)

	// Generate an ephemeral key pair with the clone.
	dE := clone.PRFScalar()
	qE := ristretto255.NewElement().ScalarBaseMult(dE)

	// Create a new Schnorr signer and ensure all headers are signed and hashed.
	signer := schnorr.NewSigner(dst)
	headers := mres.SendCLRStream(signer)

	// Encode header and allocate buffer for header ciphertexts.
	header := encodeHeader(dek, encryptedHeaderSize*uint64(len(qRs))+uint64(padding))
	encHeader := make([]byte, encryptedHeaderSize)

	// Encrypt, and write copies of the header for each recipient.
	for _, qR := range qRs {
		encHeader = hpke.Encrypt(encHeader[:0], dS, dE, qS, qE, qR, header)
		n, err := headers.Write(encHeader)
		written += int64(n)

		if err != nil {
			return written, err
		}
	}

	// Add padding to the end of the headers.
	pn, err := io.CopyN(headers, rand.Reader, int64(padding))
	written += pn

	if err != nil {
		return written, err
	}

	// Key the protocol with the DEK.
	mres.KEY(dek)

	// Encrypt the plaintext and send the ciphertext.
	pn, err = io.Copy(mres.SendENCStream(signer), src)
	written += pn

	if err != nil {
		return written, err
	}

	// Create a Schnorr signature of the entire ciphertext.
	sig, err := signer.Sign(dE, qE)
	if err != nil {
		return written, err
	}

	// Encrypt and write the signature.
	n, err := dst.Write(mres.SendENC(sig[:0], sig))
	written += int64(n)

	return written, err
}

// Decrypt reads the contents of src, decrypts them iff the owner of qS encrypted them for
// decryption by dR, and writes the decrypted contents to dst.
func Decrypt(dst io.Writer, src io.Reader, dR *ristretto255.Scalar, qR, qS *ristretto255.Element) (int64, error) {
	mres := initProtocol(qS)

	// Create a new Schnorr verifier.
	verifier := schnorr.NewVerifier(io.Discard)

	// Find a decryptable header and pass the headers through the protocol and the verifier.
	dek, qE, err := findHeader(mres.RecvCLRStream(verifier), src, dR, qR, qS)
	if err != nil {
		return 0, err
	}

	// Key the protocol with the DEK.
	mres.KEY(dek)

	// Detach the signature from the end of the ciphertext.
	sigr := sigio.NewReader(src)

	// Decrypt the message ciphertext and write it to dst.
	pn, err := io.Copy(io.MultiWriter(mres.RecvENCStream(dst), verifier), sigr)
	if err != nil {
		return pn, err
	}

	// Decrypt and verify the signature.
	if !verifier.Verify(qE, mres.RecvENC(sigr.Signature[:0], sigr.Signature)) {
		return pn, internal.ErrInvalidCiphertext
	}

	return pn, nil
}

func findHeader(
	dst io.Writer, src io.Reader, dR *ristretto255.Scalar, qR, qS *ristretto255.Element,
) ([]byte, *ristretto255.Element, error) {
	headerOffset := int64(0)
	encHeader := make([]byte, encryptedHeaderSize)

	// Iterate through the possible headers, attempting to decrypt each of them.
	for {
		// Read a possible header. If we hit the end of the file, we didn't find a header we could
		// decrypt, so the ciphertext is invalid.
		_, err := io.ReadFull(src, encHeader)
		if err != nil {
			return nil, nil, invalidCiphertextIfEOF(err)
		}

		// Record the encrypted headers in the STROBE protocol and the Schnorr verifier.
		_, _ = dst.Write(encHeader)
		headerOffset += encryptedHeaderSize

		// Try to decrypt the header.
		qE, plaintext, err := hpke.Decrypt(encHeader[:0], dR, qR, qS, encHeader)
		if err != nil {
			// If we can't decrypt it, try the next one.
			continue
		}

		// Read the remaining headers and any padding.
		messageOffset := int64(binary.LittleEndian.Uint64(plaintext[dekSize:]))
		if _, err := io.CopyN(dst, src, messageOffset-headerOffset); err != nil {
			return nil, nil, err
		}

		// Return the authenticated DEK and the ephemeral public key.
		return plaintext[:dekSize], qE, nil
	}
}

func initProtocol(qS *ristretto255.Element) *protocol.Protocol {
	// Initialize a new protocol.
	mres := protocol.New("veil.mres")

	// Add the DEK size as associated metadata.
	mres.MetaAD(protocol.LittleEndianU32(dekSize))

	// Add the sender's public key as associated data.
	mres.AD(qS.Encode(nil))

	return mres
}

func invalidCiphertextIfEOF(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return internal.ErrInvalidCiphertext
	}

	return err
}

func encodeHeader(dek []byte, messageOffset uint64) []byte {
	header := make([]byte, dekSize+8, headerSize)
	copy(header, dek)

	binary.LittleEndian.PutUint64(header[dekSize:], messageOffset)

	return header
}

const (
	dekSize             = 32
	headerSize          = dekSize + 8
	encryptedHeaderSize = headerSize + hpke.Overhead
)

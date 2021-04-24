// Package mres provides the underlying STROBE protocol for Veil's multi-recipient encryption
// system.
//
// Encryption
//
// Encrypting a message begins as follows, given the sender's key pair, d_s and Q_s, a plaintext
// message in blocks P_0…P_n, a list of recipient public keys, Q_r0..Q_rm, a randomly generated data
// encryption key, K_dek, a randomly generated W-OTS key pair, K_s and K_v, and a DEK size N_dek:
//
//  INIT('veil.mres', level=256)
//  AD(LE_32(N_dek),  meta=true)
//  AD(Q_s)
//  SEND_CLR(K_v)
//
// The data encryption key and the length of the encrypted headers (plus padding) are encoded into a
// fixed-length header and copies of it are encrypted with veil.atkem for each recipient, using the
// W-OTS verification key as the tag. Optional random padding is added to the end, and the resulting
// block H is written:
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
// Finally, a W-OTS signature S of the entire ciphertext (headers, padding, and DEM ciphertext) is
// created and written:
//
//  SEND_CLR(S)
//
// The resulting ciphertext then contains, in order: the W-OTS verification key,
// veil.atkem-encrypted headers, random padding, message ciphertext, and a W-OTS signature of the
// headers, padding, and ciphertext.
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
// The W-OTS verification key is read:
//
//  RECV_CLR(V_k)
//
// The recipient then reads through the ciphertext in header-sized blocks, looking for one which is
// decryptable given their key pair, the sender's public key, and the W-OTS verification key as the
// tag. Having found one, they recover the data encryption key K_dek and the message length and read
// the remainder of the block of encrypted headers and padding H:
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
// Finally, the signature S is read and verified against the entire ciphertext:
//
//  RECV_CLR(S)
//
// Multi-Recipient Confidentiality
//
// This construction is a simplification of Wei et al.'s heterogeneous MRES
// (https://sites.uab.edu/yzheng/files/2020/01/ispec14_in_proceedings.pdf), in that it standardizes
// on a common KEM, and as such inherits Wei's proof of IND-CCA2 security, provided the KEM is
// IND-CCA2-secure, the DEM is IND-OPA-secure, and the one-time signature scheme is SUF-CMA-secure.
// veil.atkem, STROBE's SEND/RECV_ENC operations, and veil.wots meet those requirements. As such, an
// attacker with a sender's encryption oracle and a per-recipient decryption oracle has negligible
// advantage in any IND-CCA game across any recipient.
//
// Multi-Recipient Authenticity
//
// Similarly, an attacker engaged in parallel CMA games with recipients has negligible advantage in
// forging messages. The W-OTS signature covers the entirety of the ciphertext except for the W-OTS
// verification key, but the header ciphertexts are cryptographically dependent on that same key.
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
// veil.mres eliminates this attack by binding the KEM ciphertext to the W-OTS verification key and
// including a W-OTS signature of the entire ciphertext. Re-using the KEM ciphertexts with a new
// message requires forging a new signature for a SUF-CMA-secure scheme. The use of an authenticated
// KEM serves to authenticate both the headers and the message: only the possessor of the sender's
// private key can calculate the static shared secret used to encrypt the ephemeral public key, and
// the recipient's ability to forge KEM ciphertexts is rendered moot by the KEM ciphertext's
// dependency on the W-OTS verification key.
//
// Repudiability
//
// Because the sender's private key is only used to calculate shared secrets, a veil.mres ciphertext
// is entirely repudiable unless a recipient reveals their public key. The W-OTS keys are randomly
// generated for each message and all other forms of sender identity which are transmitted are only
// binding on public information.
//
package mres

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/codahale/veil/pkg/veil/internal/atkem"
	"github.com/codahale/veil/pkg/veil/internal/protocol"
	"github.com/codahale/veil/pkg/veil/internal/sigio"
	"github.com/codahale/veil/pkg/veil/internal/wots"
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

	// Generate a DEK.
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return 0, fmt.Errorf("error generating DEK: %w", err)
	}

	// Create a new W-OTS signer.
	signer, err := wots.NewSigner(dst)
	if err != nil {
		return 0, err
	}

	// Send the W-OTS public key.
	mres.SendCLR(signer.PublicKey)

	// Write the W-OTS public key.
	n, err := dst.Write(signer.PublicKey)
	written += int64(n)

	if err != nil {
		return written, err
	}

	// Allocate buffers for the headers.
	header := make([]byte, headerSize)
	encHeader := make([]byte, encryptedHeaderSize)

	// Encode the DEK and the total size of the encrypted headers as a header.
	copy(header, dek)
	binary.LittleEndian.PutUint64(header[dekSize:], encryptedHeaderSize*uint64(len(qRs))+uint64(padding))

	// Ensure all headers are signed and recorded in the protocol.
	headers := mres.SendCLRStream(signer)

	// Encrypt, and write copies of the header using the W-OTS public key as a tag.
	for _, qR := range qRs {
		encHeader, err = atkem.Encrypt(encHeader[:0], dS, qS, qR, signer.PublicKey, header)
		if err != nil {
			return written, err
		}

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

	// Create a W-OTS signature.
	sig := signer.Sign()

	// Write the signature
	n, err = dst.Write(sig)
	written += int64(n)

	return written, err
}

// Decrypt reads the contents of src, decrypts them iff the owner of qS encrypted them for
// decryption by dR, and writes the decrypted contents to dst.
//nolint:gocognit // This gets worse if split up into functions.
func Decrypt(dst io.Writer, src io.Reader, dR *ristretto255.Scalar, qR, qS *ristretto255.Element) (int64, error) {
	mres := initProtocol(qS)

	// Read the W-OTS public key.
	verifyingKey := make([]byte, wots.PublicKeySize)
	if _, err := io.ReadFull(src, verifyingKey); err != nil {
		return 0, err
	}

	// Receive the W-OTS public key.
	mres.RecvCLR(verifyingKey)

	// Create a verifier with the W-OTS public key.
	verifier := wots.NewVerifier(verifyingKey)

	// Pass the headers through the protocol and the verifier.
	headers := mres.RecvCLRStream(verifier)

	var (
		dek        []byte
		headerRead int64
		headerLen  int64

		encHeader = make([]byte, encryptedHeaderSize)
	)

	// Iterate through the possible headers, attempting to decrypt each of them.
	for {
		// Read a possible header. If we hit the end of the file, we didn't find a header we could
		// decrypt, so the ciphertext is invalid.
		_, err := io.ReadFull(src, encHeader)
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return 0, internal.ErrInvalidCiphertext
		} else if err != nil {
			return 0, err
		}

		// Record the encrypted headers in the STROBE protocol and the W-OTS verifier.
		_, _ = headers.Write(encHeader)
		headerRead += encryptedHeaderSize

		// Try to decrypt the header.
		plaintext, err := atkem.Decrypt(encHeader[:0], dR, qR, qS, verifyingKey, encHeader)
		if err != nil {
			// If we can't decrypt it, try the next one.
			continue
		}

		// If we can decrypt the header, recover the DEK and the length of the headers.
		dek = plaintext[:dekSize]
		headerLen = int64(binary.LittleEndian.Uint64(plaintext[dekSize:]))

		// Break out to decrypt the full message.
		break
	}

	// Read the remaining headers and any padding.
	if _, err := io.CopyN(headers, src, headerLen-headerRead); err != nil {
		return 0, err
	}

	// Key the protocol with the DEK.
	mres.KEY(dek)

	sigr := sigio.NewReader(src, wots.SignatureSize)

	pn, err := io.Copy(io.MultiWriter(mres.RecvENCStream(dst), verifier), sigr)
	if err != nil {
		return pn, err
	}

	if !verifier.Verify(sigr.Signature) {
		return pn, internal.ErrInvalidCiphertext
	}

	return pn, nil
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

const (
	dekSize             = 32
	headerSize          = dekSize + 8 + 8
	encryptedHeaderSize = headerSize + atkem.Overhead
)

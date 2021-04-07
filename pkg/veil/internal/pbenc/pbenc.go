// Package pbenc implements memory-hard password-based encryption via STROBE using balloon hashing.
//
// The protocol is initialized as follows, given a passphrase P, salt S, space parameter X, time
// parameter Y, block size N, and tag size T:
//
//     INIT('veil.kdf.balloon',  level=256)
//     AD(LE_U32(X), meta=true)
//     AD(LE_U32(Y), meta=true)
//     AD(LE_U32(N), meta=true)
//     AD(LE_U32(T), meta=true)
//     KEY(P)
//     AD(S)
//
// Then, for each iteration of the balloon hashing algorithm, given a counter C, a left block L, and
// a right block R:
//
//     AD(LE_U64(C))
//     AD(L)
//     AD(R)
//     PRF(N)
//
// The final block B_n of the balloon hashing algorithm is then used to key the protocol:
//
//     KEY(B_n)
//
// Encryption of a message M is as follows:
//
//     SEND_ENC(M)
//     SEND_MAC(T)
//
// The ciphertext C and tag T are returned.
//
// Decryption of a ciphertext C and tag T is as follows:
//
//     RECV_ENC(C)
//     RECV_MAC(T)
//
// If the RECV_MAC call is successful, the plaintext is returned.
//
// It should be noted that there is no standard balloon hashing algorithm, so this protocol is in
// the very, very tall grass of cryptography and should never be used.
//
// See https://eprint.iacr.org/2016/027.pdf
package pbenc

import (
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/sammyne/strobe"
)

// Encrypt encrypts the plaintext with the passphrase and salt.
func Encrypt(passphrase, salt, plaintext []byte, space, time, n, tagSize int) []byte {
	pbenc := initProtocol(passphrase, salt, space, time, n, tagSize)

	ciphertext := make([]byte, len(plaintext)+tagSize)
	copy(ciphertext, plaintext)

	internal.MustENC(pbenc.SendENC(ciphertext[:len(plaintext)], &strobe.Options{}))

	internal.Must(pbenc.SendMAC(ciphertext[len(plaintext):], &strobe.Options{}))

	return ciphertext
}

// Decrypt decrypts the ciphertext with the passphrase and salt.
func Decrypt(passphrase, salt, ciphertext []byte, space, time, n, tagSize int) ([]byte, error) {
	pbenc := initProtocol(passphrase, salt, space, time, n, tagSize)

	plaintext := make([]byte, len(ciphertext)-tagSize)
	copy(plaintext, ciphertext[:len(ciphertext)-tagSize])

	internal.MustENC(pbenc.RecvENC(plaintext, &strobe.Options{}))

	if err := pbenc.RecvMAC(ciphertext[len(ciphertext)-tagSize:], &strobe.Options{}); err != nil {
		return nil, err
	}

	return plaintext, nil
}

func initProtocol(passphrase, salt []byte, space, time, n, tagSize int) *strobe.Strobe {
	n += n % 2 // round up

	// Initialize a new protocol.
	pbenc := internal.Strobe("veil.pbenc")

	// Include the space parameter as associated data.
	internal.Must(pbenc.AD(internal.LittleEndianU32(space), &strobe.Options{Meta: true}))

	// Include the time parameter as associated data.
	internal.Must(pbenc.AD(internal.LittleEndianU32(time), &strobe.Options{Meta: true}))

	// Include the size parameter as associated data.
	internal.Must(pbenc.AD(internal.LittleEndianU32(n), &strobe.Options{Meta: true}))

	// Include the tag size as associated data.
	internal.Must(pbenc.AD(internal.LittleEndianU32(tagSize), &strobe.Options{Meta: true}))

	// Key the protocol with the passphrase.
	internal.Must(pbenc.KEY(internal.Copy(passphrase), false))

	// Include the salt as associated data.
	internal.Must(pbenc.AD(salt, &strobe.Options{}))

	// Allocate a 64-bit counter and a buffer for its encoding.
	var (
		ctr    uint64
		ctrBuf [8]byte
	)

	// Allocate an index block.
	idx := make([]byte, n)

	// Allocate blocks.
	buf := make([]byte, space*n)

	// Initialize first block.
	hashCounter(pbenc, &ctr, ctrBuf[:], buf[0:n], nil, nil)

	// Initialize all other blocks.
	for m := 1; m < space-1; m++ {
		hashCounter(pbenc, &ctr, ctrBuf[:], buf[(m*n):(m*n)+n], buf[(m-1)*n:(m-1)*n+n], nil)
	}

	// Mix buffer contents.
	for t := 1; t < time; t++ {
		for m := 1; m < space; m++ {
			// Hash last and current blocks.
			j := (m - 1) % space
			hashCounter(pbenc, &ctr, ctrBuf[:], buf[m*n:m*n+n], buf[j*n:j*n+n], buf[m*n:m*n+n])

			// Hash pseudo-randomly chosen blocks.
			for i := 0; i < delta; i++ {
				// Map indexes to a block and hash it and the salt.
				binary.LittleEndian.PutUint32(idx[0:], uint32(t))
				binary.LittleEndian.PutUint32(idx[4:], uint32(m))
				binary.LittleEndian.PutUint32(idx[8:], uint32(i))
				hashCounter(pbenc, &ctr, ctrBuf[:], idx, salt, idx)

				// Map the hashed index block back to an index and hash that block.
				other := int(binary.LittleEndian.Uint64(idx) % uint64(space))
				hashCounter(pbenc, &ctr, ctrBuf[:], buf[m*n:m*n+n], buf[other*n:other*n+n], nil)
			}
		}
	}

	// Finally, key the protocol with the final block.
	internal.Must(pbenc.KEY(buf[(space-1)*n:], false))

	return pbenc
}

func hashCounter(pbenc *strobe.Strobe, ctr *uint64, ctrBuf, dst, left, right []byte) {
	// Increment the counter.
	*ctr++

	// Encode the counter as a little-endian value.
	binary.LittleEndian.PutUint64(ctrBuf, *ctr)

	// Hash the counter.
	internal.Must(pbenc.AD(ctrBuf, &strobe.Options{}))

	// Hash the left block.
	internal.Must(pbenc.AD(left, &strobe.Options{}))

	// Hash the right block.
	internal.Must(pbenc.AD(right, &strobe.Options{}))

	// Extract a new block.
	internal.Must(pbenc.PRF(dst, false))
}

const (
	delta = 3 // Delta is the number of dependencies per block.
)

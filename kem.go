package veil

import (
	"crypto/sha256"
	"io"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
)

const (
	kemKeyLen   = 32
	kemOverhead = kemKeyLen + poly1305.TagSize
)

// kemEncrypt encrypts the given plaintext using the initiator's X25519 secret key, the recipient's
// X25519 public key, and optional authenticated data.
func kemEncrypt(rand io.Reader, skI SecretKey, pkR PublicKey, plaintext, data []byte) ([]byte, error) {
	// Generate an ephemeral X25519 key pair.
	pkE, rkE, skE, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	// Calculate the X25519 shared secret between the ephemeral secret key and the recipient's
	// X25519 public key.
	zzE := x25519(skE, pkR)

	// Calculate the X25519 shared secret between the initiator's secret key and the recipient's
	// X25519 public key.
	zzS := x25519(skI, pkR)

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key from the shared secret.
	kn := kdf(zz, pkE, pkR, data)

	// Encrypt the plaintext with the DEM using the derived key, the derived nonce, and the
	// ephemeral public key representative as the authenticated data.
	aead, _ := chacha20poly1305.New(kn[:chacha20poly1305.KeySize])
	return aead.Seal(rkE, kn[chacha20poly1305.KeySize:], plaintext, data), nil
}

// kemDecrypt decrypts the given ciphertext using the recipient's secret key, the recipient's public
// key, the initiator's public key, and optional authenticated data. If the ciphertext can be
// decrypted, there are strong assurances that the holder of the initiator's secret key created the
// ciphertext.
func kemDecrypt(skR SecretKey, pkR, pkI PublicKey, ciphertext, data []byte) ([]byte, error) {
	// Convert the embedded Elligator2 representative to an X25519 public key.
	var rkE, pkE [32]byte
	copy(rkE[:], ciphertext[:kemKeyLen])
	extra25519.RepresentativeToPublicKey(&pkE, &rkE)

	// Calculate the X25519 shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE := x25519(skR, pkE[:])

	// Calculate the X25519 shared secret between the recipient's secret key and the initiator's
	// public key.
	zzS := x25519(skR, pkI)

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key from both the ephemeral shared secret and the static shared secret.
	kn := kdf(zz, pkE[:], pkR, data)

	// Encrypt the plaintext with the DEM using the derived key, the derived nonce, and the
	// ephemeral public key representative as the authenticated data.
	aead, _ := chacha20poly1305.New(kn[:chacha20poly1305.KeySize])
	return aead.Open(nil, kn[chacha20poly1305.KeySize:], ciphertext[kemKeyLen:], data)
}

// kdf returns a ChaCha20Poly1305 key and nonce derived from the given initial keying material,
// ephemeral public key, recipient's public key, and authenticated data.
func kdf(ikm, pkE, pkR, data []byte) []byte {
	// Create a salt consisting of the ephemeral public key and the recipient's public key.
	salt := make([]byte, len(pkE)+len(pkR))
	copy(salt, pkE)
	copy(salt[:len(pkE)], pkR)

	// Create an HKDF-SHA-256 instance from the initial keying material, the salt, and the
	// authenticated data.
	h := hkdf.New(sha256.New, ikm, salt, data)

	// Derive the key and nonce from the HKDF output.
	out := make([]byte, chacha20poly1305.KeySize+chacha20poly1305.NonceSize)
	_, _ = io.ReadFull(h, out)
	return out
}

// ephemeralKeys generate an X25519 key pair and returns the public key, the Elligator2
// representative of the public key, and the secret key.
func ephemeralKeys(rand io.Reader) ([]byte, []byte, []byte, error) {
	var sk, rk, pk [32]byte
	// Not all key pairs can be represented by Elligator2, so try until we find one.
	for {
		// Generate a random X25519 secret key.
		_, err := io.ReadFull(rand, sk[:])
		if err != nil {
			return nil, nil, nil, err
		}

		// Calculate the corresponding X25519 public key and its Elligator2 representative.
		if extra25519.ScalarBaseMult(&pk, &rk, &sk) {
			return pk[:], rk[:], sk[:], nil
		}
	}
}

// x25519 calculates the X25519 shared secret for the given secret and public keys.
func x25519(sk, pk []byte) []byte {
	var in, base, dst [32]byte
	copy(in[:], sk)
	copy(base[:], pk)

	// Calculate the shared secret.
	curve25519.ScalarMult(&dst, &in, &base)
	return dst[:]
}

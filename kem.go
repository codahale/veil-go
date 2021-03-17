package veil

import (
	"io"

	"github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
)

const (
	// The length of an Elligator2 representative for a Ristretto255 public key.
	kemPublicKeyLen = 32
	kemOverhead     = kemPublicKeyLen + poly1305.TagSize // Total overhead of KEM envelope.
)

// kemEncrypt encrypts the given plaintext using the initiator's Ristretto255/DH secret key, the
// recipient's Ristretto255/DH public key, and optional authenticated data.
func kemEncrypt(
	rand io.Reader, skI *ristretto.Scalar, pkI, pkR *ristretto.Point, plaintext, data []byte,
) ([]byte, error) {
	// Generate an ephemeral Ristretto255/DH key pair.
	_, rkE, skE, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the ephemeral secret key and the
	// recipient's Ristretto255/DH public key.
	zzE, err := xdh(&skE, pkR)
	if err != nil {
		return nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the initiator's secret key and the
	// recipient's Ristretto255/DH public key.
	zzS, err := xdh(skI, pkR)
	if err != nil {
		return nil, err
	}

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key and nonce from the shared secret, the authenticated data, the ephemeral public
	// key's Elligator2 representative, and the public keys of both the recipient and the initiator.
	key, nonce := kdf(zz, data, rkE, pkR, pkI)

	// Encrypt the plaintext DEM using the derived key, the derived nonce, and the the authenticated
	// data. Prepend the ephemeral public key's Elligator2 representative and return.
	aead, _ := chacha20poly1305.New(key)
	ciphertext := aead.Seal(rkE, nonce, plaintext, data)

	return ciphertext, nil
}

// kemDecrypt decrypts the given ciphertext using the recipient's secret key, the recipient's public
// key, the initiator's public key, and optional authenticated data. If the ciphertext can be
// decrypted, there are strong assurances that the holder of the initiator's secret key created the
// ciphertext.
func kemDecrypt(pkI, pkR *ristretto.Point, skR *ristretto.Scalar, ciphertext, data []byte) ([]byte, error) {
	// Parse out the Elligator2 representative and the remaining ciphertext.
	rkE, ciphertext := ciphertext[:kemPublicKeyLen], ciphertext[kemPublicKeyLen:]

	// Convert the embedded Elligator2 representative to a Ristretto255/DH public key.
	pkE := rk2pk(rkE)

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the
	// ephemeral public key.
	zzE, err := xdh(skR, &pkE)
	if err != nil {
		return nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the
	// initiator's public key.
	zzS, err := xdh(skR, pkI)
	if err != nil {
		return nil, err
	}

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key from the shared secret, the authenticated data, the ephemeral public key's
	// Elligator2 representative, and the public keys of both the recipient and the initiator.
	key, nonce := kdf(zz, data, rkE, pkR, pkI)

	// Encrypt the plaintext with the DEM using the derived key, the derived nonce, and the
	// ephemeral public key representative as the authenticated data.
	aead, _ := chacha20poly1305.New(key)
	plaintext, err := aead.Open(nil, nonce, ciphertext, data)

	return plaintext, err
}

// kdf returns a ChaCha20Poly1305 key and nonce derived from the given initial keying material, the
// authenticated data, the Elligator2 representative of the ephemeral key, the recipient's public
// key, and the initiator's public key.
func kdf(ikm, data, rkE []byte, pkR, pkI *ristretto.Point) ([]byte, []byte) {
	// Create a salt consisting of the Elligator2 representative of the ephemeral key, the
	// recipient's public key, and the initiator's public key.
	salt := append([]byte(nil), rkE...)
	salt = append(salt, pkR.Bytes()...)
	salt = append(salt, pkI.Bytes()...)

	// Create an HKDF-SHA-256 instance from the initial keying material, the salt, and the
	// authenticated data.
	h := hkdf.New(sha3.New512, ikm, salt, data)

	// Derive the key from the HKDF output.
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(h, key)

	// Derive the nonce from the HKDF output.
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, _ = io.ReadFull(h, nonce)

	return key, nonce
}

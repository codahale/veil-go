package veil

import (
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
)

const (
	kemKeyLen    = 32
	kemOverhead  = kemKeyLen + poly1305.TagSize
	kdfOutputLen = chacha20poly1305.KeySize + chacha20poly1305.NonceSize
)

// kemEncrypt encrypts the given plaintext using the initiator's Ristretto255/DH secret key, the recipient's
// Ristretto255/DH public key, and optional authenticated data.
func kemEncrypt(rand io.Reader, pkI PublicKey, skI SecretKey, pkR PublicKey, plaintext, data []byte) ([]byte, error) {
	// Generate an ephemeral Ristretto255/DH key pair.
	pkE, rkE, skE, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the ephemeral secret key and the recipient's
	// Ristretto255/DH public key.
	zzE, err := xdh(skE, pkR)
	if err != nil {
		return nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the initiator's secret key and the recipient's
	// Ristretto255/DH public key.
	zzS, err := xdh(skI, pkR)
	if err != nil {
		return nil, err
	}

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key from the shared secret.
	kn := kdf(zz, pkI, pkE, pkR, data)

	// Encrypt the plaintext DEM using the derived key, the derived nonce, and the
	// ephemeral public key representative as the authenticated data.
	aead, _ := chacha20poly1305.New(kn[:chacha20poly1305.KeySize])

	return aead.Seal(rkE, kn[chacha20poly1305.KeySize:], plaintext, data), nil
}

// kemDecrypt decrypts the given ciphertext using the recipient's secret key, the recipient's public
// key, the initiator's public key, and optional authenticated data. If the ciphertext can be
// decrypted, there are strong assurances that the holder of the initiator's secret key created the
// ciphertext.
func kemDecrypt(pkR PublicKey, skR SecretKey, pkI PublicKey, ciphertext, data []byte) ([]byte, error) {
	// Convert the embedded Elligator2 representative to an Ristretto255/DH public key.
	rkE := ciphertext[:kemKeyLen]
	pkE := rk2pk(rkE)

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE, err := xdh(skR, pkE)
	if err != nil {
		return nil, err
	}

	// Calculate the Ristretto255/DH shared secret between the recipient's secret key and the initiator's
	// public key.
	zzS, err := xdh(skR, pkI)
	if err != nil {
		return nil, err
	}

	// Concatenate the two to form the shared secret.
	zz := append(zzE, zzS...)

	// Derive the key from both the ephemeral shared secret and the static shared secret.
	kn := kdf(zz, pkI, pkE, pkR, data)

	// Encrypt the plaintext with the DEM using the derived key, the derived nonce, and the
	// ephemeral public key representative as the authenticated data.
	aead, _ := chacha20poly1305.New(kn[:chacha20poly1305.KeySize])

	return aead.Open(nil, kn[chacha20poly1305.KeySize:], ciphertext[kemKeyLen:], data)
}

// kdf returns a ChaCha20Poly1305 key and nonce derived from the given initial keying material,
// initiator's public key, ephemeral public key, recipient's public key, and authenticated data.
func kdf(ikm, pkI, pkE, pkR, data []byte) []byte {
	// Create a salt consisting of the initiator's public key, the ephemeral public key and the
	// recipient's public key.
	salt := append([]byte(nil), pkI...)
	salt = append(salt, pkE...)
	salt = append(salt, pkR...)

	// Create an HKDF-SHA-256 instance from the initial keying material, the salt, and the
	// authenticated data.
	h := hkdf.New(sha3.New512, ikm, salt, data)

	// Derive the key and nonce from the HKDF output.
	out := make([]byte, kdfOutputLen)
	_, _ = io.ReadFull(h, out)

	return out
}

// ephemeralKeys generate an Ristretto255/DH key pair and returns the public key, the Elligator2
// representative of the public key, and the secret key.
func ephemeralKeys(rand io.Reader) ([]byte, []byte, []byte, error) {
	sk := make([]byte, 32)

	// Not all key pairs can be represented by Elligator2, so try until we find one.
	for {
		// Generate a random Ristretto255/DH secret key.
		_, err := io.ReadFull(rand, sk)
		if err != nil {
			return nil, nil, nil, err
		}

		// Calculate the corresponding Ristretto255/DH public key and its Elligator2 representative.
		if pk, rk, err := sk2pkrk(sk); err == nil {
			return pk, rk, sk, nil
		}
	}
}

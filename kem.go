package veil

import (
	"io"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

const (
	kemPubKeyLen = 32
	kemOverhead  = kemPubKeyLen + demOverhead
)

// kemEncrypt encrypts the given plaintext with the given X25519 public key.
func kemEncrypt(rand io.Reader, public []byte, plaintext []byte) ([]byte, error) {
	// Generate an ephemeral X25519 private key and the Elligator2 representative of its public key.
	_, representative, private, err := ephemeralKeys(rand)
	if err != nil {
		return nil, err
	}

	// Calculate the X25519 shared secret between the ephemeral private key and the X25519 public
	// key.
	key := x25519(private, public)

	// Encrypt the plaintext with the DEM using the shared secret as the key and the ephemeral
	// public key representative as the authenticated data.
	ciphertext, err := demEncrypt(rand, key, plaintext, representative)
	if err != nil {
		return nil, err
	}

	// Return the ephemeral public key representative and the DEM ciphertext.
	return append(representative, ciphertext...), nil
}

// kemDecrypt decrypts the given ciphertext using the given X25519 private key.
func kemDecrypt(private []byte, ciphertext []byte) ([]byte, error) {
	// Convert the embedded Elligator2 representative to an X25519 public key.
	var representative, public [32]byte
	copy(representative[:], ciphertext[:kemPubKeyLen])
	extra25519.RepresentativeToPublicKey(&public, &representative)

	// Calculate the X25519 shared secret.
	key := x25519(private, public[:])

	// Decrypt the ciphertext with the shared secret.
	return demDecrypt(key, ciphertext[kemPubKeyLen:], representative[:])
}

// ephemeralKeys generate an X25519 key pair and returns the public key, the Elligator2
// representative of the public key, and the private key.
func ephemeralKeys(rand io.Reader) ([]byte, []byte, []byte, error) {
	var privateKey, representative, publicKey [32]byte
	// Not all key pairs can be represented by Elligator2, so try until we find one.
	for {
		// Generate a random X25519 private key.
		_, err := io.ReadFull(rand, privateKey[:])
		if err != nil {
			return nil, nil, nil, err
		}

		// Calculate the corresponding X25519 public key and its Elligator2 representative.
		if extra25519.ScalarBaseMult(&publicKey, &representative, &privateKey) {
			return publicKey[:], representative[:], privateKey[:], nil
		}
	}
}

// x25519 calculates the X25519 shared secret for the given private and public keys.
func x25519(private []byte, public []byte) []byte {
	var xPrivate, xPublic, dst [32]byte
	copy(xPrivate[:], private)
	copy(xPublic[:], public)

	// Calculate the shared secret.
	curve25519.ScalarMult(&dst, &xPrivate, &xPublic)
	return dst[:]
}

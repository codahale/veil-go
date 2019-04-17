package veil

import (
	"crypto/rand"
	"io"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const (
	kemPubKeyLen = 32
	kemOverhead  = kemPubKeyLen + demOverhead
)

// kemEncrypt encrypts the given plaintext with the given Ed25519 public key.
func kemEncrypt(public ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	// Generate an ephemeral X25519 private key and the Elligator2 representative of its public key.
	representative, private, err := ephemeralKeys()
	if err != nil {
		return nil, err
	}

	// Calculate the X25519 shared secret between the ephemeral private key and the Ed25519 public
	// key.
	key := xdhSend(private, public)

	// Encrypt the plaintext with the DEM using the shared secret as the key and the ephemeral
	// public key representative as the authenticated data.
	ciphertext, err := demEncrypt(key[:], plaintext, representative)
	if err != nil {
		return nil, err
	}

	// Return the ephemeral public key representative and the DEM ciphertext.
	return append(representative, ciphertext...), nil
}

// kemDecrypt decrypts the given ciphertext using the given Ed25519 private key.
func kemDecrypt(private ed25519.PrivateKey, ciphertext []byte) ([]byte, error) {
	representative := ciphertext[:kemPubKeyLen]
	key := xdhReceive(private, representative)
	return demDecrypt(key, ciphertext[kemPubKeyLen:], representative)
}

// ephemeralKeys returns an X25519 in the form of the Elligator2 representative of the public key
// and its corresponding private key.
func ephemeralKeys() ([]byte, []byte, error) {
	var privateKey, representative, publicKey [32]byte
	// Not all key pairs can be represented by Elligator2, so try until we find one.
	for {
		// Generate a random X25519 private key.
		_, err := io.ReadFull(rand.Reader, privateKey[:])
		if err != nil {
			return nil, nil, err
		}

		// Calculate the corresponding X25519 public key and its Elligator2 representative.
		if extra25519.ScalarBaseMult(&publicKey, &representative, &privateKey) {
			return representative[:], privateKey[:], nil
		}
	}
}

// xdhReceive computes the X25519 shared secret between an Ed25519 private key and the Elligator2
// representative of an X25519 public key.
func xdhReceive(private ed25519.PrivateKey, ephemeral []byte) []byte {
	var edPrivate [64]byte
	var xPrivate, xPublic, representative, dst [32]byte
	copy(edPrivate[:], private)
	copy(representative[:], ephemeral)

	// Convert the Ed25519 private key to X25519.
	extra25519.PrivateKeyToCurve25519(&xPrivate, &edPrivate)

	// Convert the Elligator2 representative to a X25519.
	extra25519.RepresentativeToPublicKey(&xPublic, &representative)

	// Calculate the shared secret.
	curve25519.ScalarMult(&dst, &xPrivate, &xPublic)
	return dst[:]
}

// xdhSend computes the X25519 shared secret between an X25519 private key and an Ed25519 public
// key.
func xdhSend(private []byte, public ed25519.PublicKey) []byte {
	var xPrivate, xPublic, edPublic, dst [32]byte
	copy(xPrivate[:], private)
	copy(edPublic[:], public)

	// Convert the Ed25519 public key to an X25519 public key.
	extra25519.PublicKeyToCurve25519(&xPublic, &edPublic)

	// Calculate the shared secret.
	curve25519.ScalarMult(&dst, &xPrivate, &xPublic)
	return dst[:]
}

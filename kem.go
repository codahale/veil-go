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

func kemEncrypt(static ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	// generate an ephemeral key pair
	representative, private, err := ephemeralKeys()
	if err != nil {
		return nil, err
	}

	// derive a key from the ephemeral/recipient shared secret
	key := xdhSend(private, static)

	// encrypt the plaintext w/ DEM
	ciphertext, err := demEncrypt(key[:], plaintext, representative)
	if err != nil {
		return nil, err
	}

	// return the ephemeral public key representative and the ciphertext
	out := make([]byte, 0, len(representative)+len(ciphertext))
	out = append(out, representative...)
	out = append(out, ciphertext...)
	return out, nil
}

func kemDecrypt(private ed25519.PrivateKey, ciphertext []byte) ([]byte, error) {
	representative := ciphertext[:kemPubKeyLen]
	key := xdhReceive(private, representative)
	return demDecrypt(key, ciphertext[kemPubKeyLen:], representative)
}

func ephemeralKeys() ([]byte, []byte, error) {
	var privateKey, representative, publicKey [32]byte
	for {
		// generate a random secret key
		_, err := io.ReadFull(rand.Reader, privateKey[:])
		if err != nil {
			return nil, nil, err
		}

		// check if it maps to a valid Elligator2 representative
		if extra25519.ScalarBaseMult(&publicKey, &representative, &privateKey) {
			// use the representative as the public key
			return representative[:], privateKey[:], nil
		}
	}
}

func xdhReceive(private ed25519.PrivateKey, representative []byte) []byte {
	// convert Ed25519 private key to X25519 private key
	var edPrivate [64]byte
	copy(edPrivate[:], private)
	var xPrivate [32]byte
	extra25519.PrivateKeyToCurve25519(&xPrivate, &edPrivate)

	// convert X25519 representative to X25519 public key
	var buf [32]byte
	copy(buf[:], representative)
	var xPublic [32]byte
	extra25519.RepresentativeToPublicKey(&xPublic, &buf)

	// calculate shared secret
	var dst [32]byte
	curve25519.ScalarMult(&dst, &xPrivate, &xPublic)
	return dst[:]
}

func xdhSend(private []byte, public ed25519.PublicKey) []byte {
	// copy X25519 private key
	var xPrivate [32]byte
	copy(xPrivate[:], private)

	// convert Ed25519 public key to X25519 public key
	var xPublic, edPublic [32]byte
	copy(edPublic[:], public)
	extra25519.PublicKeyToCurve25519(&xPublic, &edPublic)

	var dst [32]byte
	curve25519.ScalarMult(&dst, &xPrivate, &xPublic)
	return dst[:]
}

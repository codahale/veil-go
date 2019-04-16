package veil

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

const (
	kemPubKeyLen = 32
	kemOverhead  = kemPubKeyLen + demOverhead
)

func kemEncrypt(static ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	// generate an ephemeral key pair
	public, private, err := ephemeralKeys()
	if err != nil {
		return nil, err
	}

	// derive a key from the ephemeral/recipient shared secret
	key := kdf(xdhSend(private, static), public)

	// encrypt the plaintext w/ DEM
	ciphertext, err := demEncrypt(key, plaintext, nil)
	if err != nil {
		return nil, err
	}

	// return the ephemeral public key and the ciphertext
	out := make([]byte, 0, len(public)+len(ciphertext))
	out = append(out, public...)
	out = append(out, ciphertext...)
	return out, nil
}

func kemDecrypt(private ed25519.PrivateKey, ciphertext []byte) ([]byte, error) {
	ephemeral := ciphertext[:kemPubKeyLen]
	secret := xdhReceive(private, ephemeral)
	key := kdf(secret, ephemeral)
	return demDecrypt(key, ciphertext[kemPubKeyLen:], nil)
}

func kdf(ikm []byte, ephemeral []byte) []byte {
	// use the ephemeral public key as the HKDF salt
	h := hkdf.New(sha512.New512_256, ikm, ephemeral, []byte("veil"))
	key := make([]byte, demKeyLen)
	_, _ = io.ReadFull(h, key)
	return key
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

func xdhReceive(private ed25519.PrivateKey, public []byte) []byte {
	// convert Ed25519 private key to X25519 private key
	var edPrivate [64]byte
	copy(edPrivate[:], private)
	var xPrivate [32]byte
	extra25519.PrivateKeyToCurve25519(&xPrivate, &edPrivate)

	// convert X25519 representative to X25519 public key
	var representative [32]byte
	copy(representative[:], public)
	var xPublic [32]byte
	extra25519.RepresentativeToPublicKey(&xPublic, &representative)

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

package veil

import (
	"crypto/sha512"
	"io"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	kemPubKeyLen = 32
	kemOverhead  = kemPubKeyLen + demOverhead
)

func kemEncrypt(static PublicKey, plaintext []byte) ([]byte, error) {
	// generate an ephemeral key pair
	public, private, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	// derive a key from the ephemeral/recipient shared secret
	key := kdf(sharedSecret(private, static), public, static)

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

func kemDecrypt(private PrivateKey, public PublicKey, ciphertext []byte) ([]byte, error) {
	ephemeral := ciphertext[:kemPubKeyLen]
	secret := sharedSecret(private, ephemeral)
	key := kdf(secret, ephemeral, public)
	return demDecrypt(key, ciphertext[kemPubKeyLen:], nil)
}

func kdf(ikm []byte, ephemeral PublicKey, recipient PublicKey) []byte {
	// use the ephemeral public key and the recipient public key as the HKDF salt
	salt := make([]byte, 0, len(ephemeral)+len(recipient))
	salt = append(salt, ephemeral...)
	salt = append(salt, recipient...)
	h := hkdf.New(sha512.New512_256, ikm, salt, []byte("veil"))
	key := make([]byte, demKeyLen)
	_, _ = io.ReadFull(h, key)
	return key
}

func sharedSecret(private PrivateKey, public PublicKey) []byte {
	var dst, in, base, representative [32]byte
	copy(in[:], private)
	copy(representative[:], public)
	extra25519.RepresentativeToPublicKey(&base, &representative)
	curve25519.ScalarMult(&dst, &in, &base)
	return dst[:]
}

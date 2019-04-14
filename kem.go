package veil

import (
	"bytes"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

const kemOverhead = 32 + demOverhead

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
	out := bytes.NewBuffer(nil)
	out.Write(public)
	out.Write(ciphertext)
	return out.Bytes(), nil
}

func kemDecrypt(private PrivateKey, public PublicKey, ciphertext []byte) ([]byte, error) {
	ephemeral := ciphertext[:32]
	secret := sharedSecret(private, ephemeral)
	key := kdf(secret, ephemeral, public)
	return demDecrypt(key, ciphertext[32:], nil)
}

func kdf(ikm []byte, ephemeral PublicKey, recipient PublicKey) []byte {
	// use the ephemeral public key and the recipient public key as the HKDF salt
	salt := bytes.NewBuffer(nil)
	salt.Write(ephemeral)
	salt.Write(recipient)
	h := hkdf.New(sha512.New512_256, ikm, salt.Bytes(), []byte("veil"))
	key := make([]byte, 32)
	_, _ = io.ReadFull(h, key)
	return key
}

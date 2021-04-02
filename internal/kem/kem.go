// Package kem implements a ristretto255/XDH key encapsulation mechanism (KEM).
//
// As a One-Pass Unified Model `C(1e, 2s, ECC CDH)` key agreement scheme (per NIST SP 800-56A), this
// KEM provides assurance that the message was encrypted by the holder of the sender's private key.
// XDH mutability issues are mitigated by the inclusion of the ephemeral public key and the
// recipient's public key in the HKDF inputs. Deriving the key and nonce from the ephemeral shared
// secret eliminates the possibility of nonce misuse, results in a shorter ciphertext by eliding the
// nonce, and adds key-commitment with all public keys as openers.
package kem

import (
	"io"

	"github.com/codahale/veil/internal/r255"
)

// KDF is a generic key derivation function, accepting a secret and a salt and returning an
// io.Reader of derived data.
type KDF func(secret, salt []byte) io.Reader

// Send returns an ephemeral public key and a shared secret given the sender's private key, the
// sender's public key, the recipient's public key, a domain-specific KDF, and the length of the
// secret in bytes.
func Send(privS *r255.PrivateKey, pubS, pubR *r255.PublicKey, kdf KDF, n int) (*r255.PublicKey, []byte, error) {
	// Generate an ephemeral key pair.
	privE, pubE, err := r255.NewEphemeralKeys()
	if err != nil {
		return nil, nil, err
	}

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := privE.DiffieHellman(pubR)

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := privS.DiffieHellman(pubR)

	// Derive the secret from the shared secrets, the ephemeral public key, the public keys of both
	// the recipient and the sender, the info parameter, and the length of the secret in bytes.
	secret := extract(zzE, zzS, pubE, pubR, pubS, kdf, n)

	// Return the ephemeral public key and the shared secret.
	return pubE, secret, nil
}

// Receive generates a shared secret given the recipient's private key, the recipient's public key,
// the sender's public key, the ephemeral public key, a domain-specific KDF, and the length of the
// shared secret in bytes.
func Receive(privR *r255.PrivateKey, pubR, pubS, pubE *r255.PublicKey, kdf KDF, n int) []byte {
	// Calculate the ephemeral shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE := privR.DiffieHellman(pubE)

	// Calculate the static shared secret between the recipient's secret key and the sender's public
	// key.
	zzS := privR.DiffieHellman(pubS)

	// Derive the secret from the shared secrets, the ephemeral public key, the public keys of both
	// the recipient and the sender, the info parameter, and the length of the secret in bytes.
	return extract(zzE, zzS, pubE, pubR, pubS, kdf, n)
}

// extract returns a secret derived from the given ephemeral shared secret, static shared secret,
// the ephemeral public key, the recipient's public key, the sender's public key, a domain-specific
// KDF, and the length of the secret in bytes.
func extract(zzE, zzS []byte, pubE, pubR, pubS *r255.PublicKey, kdf KDF, n int) []byte {
	// Concatenate the ephemeral and static shared secrets to form the initial keying material.
	ikm := append(zzE, zzS...)

	// Create a salt consisting of the ephemeral public key, the recipient's public key, and the
	// sender's public key.
	salt := pubS.Encode(pubE.Encode(pubR.Encode(make([]byte, 0, r255.PublicKeySize*3))))

	// Create an KDF instance from the initial keying material and the salt.
	k := kdf(ikm, salt)

	// Derive the secret from the HKDF output.
	secret := make([]byte, n)
	if _, err := io.ReadFull(k, secret); err != nil {
		panic(err)
	}

	// Return the shared secret.
	return secret
}

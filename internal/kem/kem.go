// Package kem implements a ristretto255/XDH key encapsulation mechanism (KEM).
//
// As a One-Pass Unified Model `C(1e, 2s, ECC CDH)` key agreement scheme (per NIST SP 800-56A), this
// KEM provides assurance that the message was encrypted by the holder of the sender's secret key.
// XDH mutability issues are mitigated by the inclusion of the ephemeral public key and the
// recipient's public key in the HKDF inputs. Deriving the key and nonce from the ephemeral shared
// secret eliminates the possibility of nonce misuse, results in a shorter ciphertext by eliding the
// nonce, and adds key-commitment with all public keys as openers.
package kem

import (
	"bytes"
	"crypto/sha512"
	"io"

	"github.com/codahale/veil/internal/r255"
	"golang.org/x/crypto/hkdf"
)

// Send generates an ephemeral public key and a shared secret given the sender's secret key, the
// sender's public key, the recipient's public key, a domain-specific information parameter, and the
// length of the secret in bytes. It return an ephemeral public key and a shared secret.
func Send(skS, pkS, pkR, info []byte, n int) ([]byte, []byte, error) {
	// Generate an ephemeral key pair.
	skE, err := r255.NewSecretKey()
	if err != nil {
		return nil, nil, err
	}

	pkE := r255.PublicKey(skE)

	// Calculate the ephemeral shared secret between the ephemeral secret key and the recipient's
	// public key.
	zzE, err := r255.DiffieHellman(skE, pkR)
	if err != nil {
		return nil, nil, err
	}

	// Calculate the static shared secret between the sender's secret key and the recipient's
	// public key.
	zzS, err := r255.DiffieHellman(skS, pkR)
	if err != nil {
		return nil, nil, err
	}

	// Derive the secret from the shared secrets, the ephemeral public key, the public keys of both
	// the recipient and the sender, the info parameter, and the length of the secret in bytes.
	secret := kdf(zzE, zzS, pkE, pkR, pkS, info, n)

	// Return the ephemeral public key and the shared secret.
	return pkE, secret, nil
}

// Receive generates a shared secret given the recipient's secret key, the recipient's public key,
// the sender's public key, the ephemeral public key, a domain-specific information parameter,
// and the length of the shared secret in bytes.
func Receive(skR, pkR, pkS, pkE, info []byte, n int) ([]byte, error) {
	// Calculate the ephemeral shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE, err := r255.DiffieHellman(skR, pkE)
	if err != nil {
		return nil, err
	}

	// Calculate the static shared secret between the recipient's secret key and the sender's public
	// key.
	zzS, err := r255.DiffieHellman(skR, pkS)
	if err != nil {
		return nil, err
	}

	// Derive the secret from the shared secrets, the ephemeral public key, the public keys of both
	// the recipient and the sender, the info parameter, and the length of the secret in bytes.
	return kdf(zzE, zzS, pkE, pkR, pkS, info, n), nil
}

// kdf returns a secret derived from the given ephemeral shared secret, static shared secret, the
// ephemeral public key, the recipient's public key, the sender's public key, an info parameter, and
// the length of the secret in bytes.
func kdf(zzE, zzS, pkE, pkR, pkS, info []byte, n int) []byte {
	// Concatenate the ephemeral and static shared secrets to form the initial keying material.
	ikm := append(zzE, zzS...)

	// Create a salt consisting of the ephemeral public key, the recipient's public key, and the
	// sender's public key.
	salt := bytes.Join([][]byte{pkE, pkR, pkS}, nil)

	// Create an HKDF-SHA-512 instance from the initial keying material and the salt, using the
	// domain-specific info parameter to distinguish between header keys and message keys.
	h := hkdf.New(sha512.New, ikm, salt, info)

	// Derive the secret from the HKDF output.
	secret := make([]byte, n)
	if _, err := io.ReadFull(h, secret); err != nil {
		panic(err)
	}

	// Return the shared secret.
	return secret
}

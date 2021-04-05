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
	"github.com/codahale/veil/pkg/veil/internal/protocols/kemkdf"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
)

// Send returns an ephemeral public key and a shared secret given the sender's private key, the
// sender's public key, the recipient's public key, the length of the secret in bytes, and whether
// or not this is a header key.
func Send(
	privS *ristretto255.Scalar, pubS, pubR *ristretto255.Element, n int, header bool,
) (*ristretto255.Element, []byte, error) {
	// Generate an ephemeral key pair.
	privE, pubE, err := r255.NewEphemeralKeys()
	if err != nil {
		return nil, nil, err
	}

	// Calculate the ephemeral shared secret between the ephemeral private key and the recipient's
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(privE, pubR)

	// Calculate the static shared secret between the sender's private key and the recipient's
	// public key.
	zzS := ristretto255.NewElement().ScalarMult(privS, pubR)

	// Derive the secret from both shared secrets plus all the inputs.
	secret := kemkdf.DeriveKey(zzE, zzS, pubE, pubR, pubS, n, header)

	// Return the ephemeral public key and the shared secret.
	return pubE, secret, nil
}

// Receive generates a shared secret given the recipient's private key, the recipient's public key,
// the sender's public key, the ephemeral public key, the length of the shared secret in bytes, and
// whether or not this is a header key.
func Receive(
	privR *ristretto255.Scalar, pubR, pubS, pubE *ristretto255.Element, n int, header bool,
) []byte {
	// Calculate the ephemeral shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE := ristretto255.NewElement().ScalarMult(privR, pubE)

	// Calculate the static shared secret between the recipient's secret key and the sender's public
	// key.
	zzS := ristretto255.NewElement().ScalarMult(privR, pubS)

	// Derive the secret from both shared secrets plus all the inputs.
	return kemkdf.DeriveKey(zzE, zzS, pubE, pubR, pubS, n, header)
}

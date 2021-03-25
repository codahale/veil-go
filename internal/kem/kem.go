package kem

import (
	"crypto/sha256"
	"io"

	"github.com/bwesterb/go-ristretto"
	"github.com/codahale/veil/internal/xdh"
	"golang.org/x/crypto/hkdf"
)

// Send generates an ephemeral representative and a shared secret given the sender's secret key, the
// sender's public key, the recipient's public key, a domain-specific information parameter, and the
// length of the secret in bytes.
func Send(skS *ristretto.Scalar, pkS, pkR *ristretto.Point, info []byte, n int) ([]byte, []byte, error) {
	// Generate an ephemeral key pair.
	_, rkE, skE, err := xdh.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	// Calculate the ephemeral shared secret between the ephemeral secret key and the recipient's
	// public key.
	zzE := xdh.SharedSecret(&skE, pkR)

	// Calculate the static shared secret between the sender's secret key and the recipient's
	// public key.
	zzS := xdh.SharedSecret(skS, pkR)

	// Derive the secret from the shared secrets, the ephemeral public key's representative, the
	// public keys of both the recipient and the sender, the info parameter, and the length of the
	// secret in bytes.
	secret := kdf(zzE, zzS, rkE, pkR, pkS, info, n)

	// Return the ephemeral public key's representative, the symmetric key, and the IV.
	return rkE, secret, nil
}

// Receive generates a shared secret given the recipient's secret key, the recipient's public key,
// the sender's public key, the ephemeral representative, a domain-specific information parameter,
// and the length of the shared secret in bytes.
func Receive(skR *ristretto.Scalar, pkR, pkS *ristretto.Point, rkE, info []byte, n int) []byte {
	var pkE ristretto.Point

	// Convert the embedded representative to a public key.
	xdh.RepresentativeToPublic(&pkE, rkE)

	// Calculate the ephemeral shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE := xdh.SharedSecret(skR, &pkE)

	// Calculate the static shared secret between the recipient's secret key and the sender's public
	// key.
	zzS := xdh.SharedSecret(skR, pkS)

	// Derive the secret from the shared secrets, the ephemeral public key's representative, the
	// public keys of both the recipient and the sender, the info parameter, and the length of the
	// secret in bytes.
	return kdf(zzE, zzS, rkE, pkR, pkS, info, n)
}

// kdf returns a secret derived from the given ephemeral shared secret, static shared secret, the
// ephemeral public key's representative, the recipient's public key, the sender's public key, an
// info parameter, and the length of the secret in bytes.
func kdf(zzE, zzS, rkE []byte, pkR, pkS *ristretto.Point, info []byte, n int) []byte {
	// Concatenate the ephemeral and static shared secrets to form the initial keying material.
	ikm := append(zzE, zzS...)

	// Create a salt consisting of the ephemeral public key's representative, the recipient's public
	// key, and the sender's public key.
	salt := append(rkE, append(pkR.Bytes(), pkS.Bytes()...)...)

	// Create an HKDF-SHA256 instance from the initial keying material and the salt, using the
	// domain-specific info parameter to distinguish between header keys and message keys.
	h := hkdf.New(sha256.New, ikm, salt, info)

	// Derive the secret from the HKDF output.
	secret := make([]byte, n)
	_, _ = io.ReadFull(h, secret)

	return secret
}

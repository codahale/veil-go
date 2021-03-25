package veil

import (
	"crypto/sha256"
	"io"

	"github.com/bwesterb/go-ristretto"
	"github.com/codahale/veil/internal/xdh"
	"golang.org/x/crypto/hkdf"
)

const (
	kemOverhead = xdh.PublicKeySize + aeadOverhead // Total overhead of KEM envelope.
)

// kemSend generates an ephemeral representative, a symmetric key, and an IV given the sender's
// secret key, the sender's public key, and the recipient's public key.
func kemSend(skS *ristretto.Scalar, pkS, pkR *ristretto.Point, header bool) ([]byte, []byte, []byte, error) {
	// Generate an ephemeral key pair.
	_, rkE, skE, err := xdh.GenerateKeys()
	if err != nil {
		return nil, nil, nil, err
	}

	// Calculate the ephemeral shared secret between the ephemeral secret key and the recipient's
	// public key.
	zzE := xdh.SharedSecret(&skE, pkR)

	// Calculate the static shared secret between the sender's secret key and the recipient's
	// public key.
	zzS := xdh.SharedSecret(skS, pkR)

	// Derive the key and IV from the shared secrets, the ephemeral public key's representative, and
	// the public keys of both the recipient and the sender.
	key, iv := kdf(zzE, zzS, rkE, pkR, pkS, header)

	// Return the ephemeral public key's representative, the symmetric key, and the IV.
	return rkE, key, iv, nil
}

// kemReceive generates a symmetric key and IV given the recipient's secret key, the recipient's
// public key, the sender's public key, and the ephemeral representative.
func kemReceive(skR *ristretto.Scalar, pkR, pkS *ristretto.Point, rkE []byte, header bool) ([]byte, []byte) {
	var pkE ristretto.Point

	// Convert the embedded representative to a public key.
	xdh.RepresentativeToPublic(&pkE, rkE)

	// Calculate the ephemeral shared secret between the recipient's secret key and the ephemeral
	// public key.
	zzE := xdh.SharedSecret(skR, &pkE)

	// Calculate the static shared secret between the recipient's secret key and the sender's public
	// key.
	zzS := xdh.SharedSecret(skR, pkS)

	// Derive the key from the shared secrets, the ephemeral public key's representative, and the
	// public keys of both the recipient and sender.
	return kdf(zzE, zzS, rkE, pkR, pkS, header)
}

// kdf returns an AES-256 key and CTR IV derived from the given ephemeral shared secret, static
// shared secret, the ephemeral public key's representative, the recipient's public key, and the
// sender's public key.
func kdf(zzE, zzS, rkE []byte, pkR, pkS *ristretto.Point, header bool) ([]byte, []byte) {
	// Concatenate the ephemeral and static shared secrets to form the initial keying material.
	ikm := append(zzE, zzS...)

	// Create a salt consisting of the ephemeral public key's representative, the recipient's public
	// key, and the sender's public key.
	salt := append(rkE, append(pkR.Bytes(), pkS.Bytes()...)...)

	// Differentiate between keys derived for encrypting headers and those for encrypting messages.
	var info []byte
	if header {
		info = []byte("header")
	} else {
		info = []byte("message")
	}

	// Create an HKDF-SHA2-256 instance from the initial keying material and the salt, using the
	// domain-specific info parameter to distinguish between header keys and message keys.
	h := hkdf.New(sha256.New, ikm, salt, info)

	// Derive the key from the HKDF output.
	kn := make([]byte, aesKeySize+aeadIVSize)
	_, _ = io.ReadFull(h, kn)

	return kn[:aesKeySize], kn[aesKeySize:]
}

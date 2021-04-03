// Package dxof provides domain-separated XOF (eXtendable Output Function) implementations for Veil.
// These are all co-located to ensure the domains are cleanly separated.
package dxof

import (
	"io"

	"golang.org/x/crypto/sha3"
)

// XOF is an eXtendable Output Function.
type XOF interface {
	sha3.ShakeHash
}

// SecretKeyScalar returns an XOF suitable for deriving ristretto255 secret key scalars from
// arbitrary strings.
func SecretKeyScalar() XOF {
	return sha3.NewCShake256([]byte("veil-secret-key"), nil)
}

// PrivateKeyScalar returns an XOF suitable for deriving ristretto255 secret key scalars from
// arbitrary strings.
func PrivateKeyScalar() XOF {
	return sha3.NewCShake256([]byte("veil-private-key"), nil)
}

// LabelScalar returns an XOF suitable for deriving ristretto255 scalars from labels.
func LabelScalar() XOF {
	return sha3.NewCShake256([]byte("veil-derived-key"), nil)
}

// SignatureScalar returns an XOF suitable for deriving ristretto255 signature scalars from
// arbitrary strings.
func SignatureScalar(sigPoint []byte) XOF {
	return sha3.NewCShake256([]byte("veil-signature"), sigPoint)
}

// SignatureNonceScalar returns an XOF suitable for deriving signature nonces from private keys and
// messages. Uses the encoded private key as part of the HMAC key.
func SignatureNonceScalar(privateKey []byte) XOF {
	return sha3.NewCShake256([]byte("veil-signature-nonce"), privateKey)
}

// MessageDigest returns an XOF suitable for hashing messages.
func MessageDigest() XOF {
	return sha3.NewCShake256([]byte("veil-message-digest"), nil)
}

// SecretKeyIdentity returns a n-byte digest suitable for creating safe, unique identifiers for
// secret keys.
func SecretKeyIdentity(sk []byte, n int) []byte {
	xof := sha3.NewCShake256([]byte("veil-identity"), sk)
	h := make([]byte, n)
	_, _ = io.ReadFull(xof, h)

	return h
}

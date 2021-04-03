// Package dxof provides domain-separated XOF (eXtendable Output Function) implementations for Veil.
// These are all co-located to ensure the domains are cleanly separated.
package dxof

import (
	"io"

	"golang.org/x/crypto/sha3"
)

// SecretKeyIdentity returns a n-byte digest suitable for creating safe, unique identifiers for
// secret keys.
func SecretKeyIdentity(sk []byte, n int) []byte {
	xof := sha3.NewCShake256([]byte("veil-identity"), sk)
	h := make([]byte, n)
	_, _ = io.ReadFull(xof, h)

	return h
}

// Package ndf provides the underlying STROBE protocol for Veil's nonce derivation functions.
//
// Secret key derivation is as follows, given a random nonce R:
//
//     INIT('veil.ndf.secret-key', level=256)
//     KEY(R)
//     PRF(64)
//
// Salt derivation is as follows, given a random nonce R:
//
//     INIT('veil.ndf.salt', level=256)
//     KEY(R)
//     PRF(32)
package ndf

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
)

// SecretKey processes the given secret key in place with a derivation function to harden it against
// faulty PRNGs.
func SecretKey(sk *[64]byte) {
	skdf := protocols.New("veil.kdf.secret-key")

	protocols.Must(skdf.KEY(sk[:], false))

	protocols.Must(skdf.PRF(sk[:], false))
}

// Salt processes the given random salt in place with a derivation function to harden it against
// faulty PRNGs.
func Salt(salt *[32]byte) {
	skdf := protocols.New("veil.kdf.salt")

	protocols.Must(skdf.KEY(salt[:], false))

	protocols.Must(skdf.PRF(salt[:], false))
}

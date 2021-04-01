package scopedhash

import (
	"crypto/hmac"
	"crypto/sha512"
	"hash"
)

// NewSecretKeyHash returns a hash instance suitable for deriving ristretto255 secret key scalars
// from arbitrary strings.
func NewSecretKeyHash() hash.Hash {
	return newHash("veilsecretkey")
}

// NewSignatureHash returns a hash instance suitable for deriving ristretto255 signature scalars
// from arbitrary strings.
func NewSignatureHash() hash.Hash {
	return newHash("veilsignature")
}

// NewMessageHash returns a hash instance suitable for hashing messages.
func NewMessageHash() hash.Hash {
	return newHash("veilmessage")
}

// NewDerivedKeyHash returns a hash instance suitable for deriving ristretto255 scalars and points
// from parent scalars and points in parallel.
func NewDerivedKeyHash() hash.Hash {
	return newHash("veilderivedkey")
}

// NewIdentityHash returns a hash instance suitable for creating unique identifiers for secret keys.
func NewIdentityHash() hash.Hash {
	return newHash("veilidentity")
}

func newHash(scope string) hash.Hash {
	return hmac.New(sha512.New, []byte(scope))
}

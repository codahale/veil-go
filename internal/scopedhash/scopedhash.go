package scopedhash

import (
	"crypto/sha512"
	"hash"
	"io"
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

func newHash(scope string) hash.Hash {
	h := sha512.New()
	_, _ = io.WriteString(h, scope)

	return h
}

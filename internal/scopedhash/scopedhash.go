package scopedhash

import (
	"crypto/hmac"
	"crypto/sha512"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// NewSecretKeyHash returns a hash instance suitable for deriving ristretto255 secret key scalars
// from arbitrary strings.
func NewSecretKeyHash() hash.Hash {
	return newScopedHash([]byte("veil-secret-key"))
}

// NewSignatureHash returns a hash instance suitable for deriving ristretto255 signature scalars
// from arbitrary strings.
func NewSignatureHash() hash.Hash {
	return newScopedHash([]byte("veil-signature"))
}

// NewMessageHash returns a hash instance suitable for hashing messages.
func NewMessageHash() hash.Hash {
	return newScopedHash([]byte("veil-message"))
}

// NewDerivedKeyHash returns a hash instance suitable for deriving ristretto255 scalars and points
// from parent scalars and points in parallel.
func NewDerivedKeyHash() hash.Hash {
	return newScopedHash([]byte("veil-derived-key"))
}

// NewIdentityHash returns a hash instance suitable for creating unique identifiers for secret keys.
func NewIdentityHash() hash.Hash {
	return newScopedHash([]byte("veil-identity"))
}

// NewSignatureNonceHash returns a hash instance suitable for deriving signature nonces from private
// keys and messages. Uses the encoded private key as part of the HMAC key.
func NewSignatureNonceHash(privateKey []byte) hash.Hash {
	return newScopedHash(append([]byte("veil-signature-nonce"), privateKey...))
}

// NewMessageKDF returns a KDF suitable for deriving message keys from a KEM exchange.
func NewMessageKDF(secret, salt []byte) io.Reader {
	return hkdf.New(NewHash, secret, salt, []byte("veil-message"))
}

// NewHeaderKDF returns a KDF suitable for deriving header keys from a KEM exchange.
func NewHeaderKDF(secret, salt []byte) io.Reader {
	return hkdf.New(NewHash, secret, salt, []byte("veil-header"))
}

// NewRatchetKDF returns a KDF suitable for deriving header keys from a KEM exchange.
func NewRatchetKDF(secret, salt []byte) io.Reader {
	return hkdf.New(NewHash, secret, salt, []byte("veil-ratchet"))
}

// NewHash returns an SHA512 hash. This is the only hash algorithm used by Veil.
func NewHash() hash.Hash {
	return sha512.New()
}

// newScopedHash returns an HMAC-SHA512 keyed with the given scope.
func newScopedHash(scope []byte) hash.Hash {
	return hmac.New(NewHash, scope)
}

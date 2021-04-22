// Package veil implements the Veil hybrid cryptosystem.
//
// Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
// authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
// Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
// encrypted. As a result, a global passive adversary would be unable to gain any information from a
// Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
// true length, and fake recipients can be added to disguise their true number from other
// recipients.
//
// You should not use this.
package veil

import (
	"errors"
	"strings"

	"github.com/codahale/veil/pkg/veil/internal"
)

var (
	// ErrInvalidCiphertext is returned when a ciphertext cannot be decrypted, either due to an
	// incorrect key or tampering.
	ErrInvalidCiphertext = internal.ErrInvalidCiphertext

	// ErrInvalidSignature is returned when a signature, public key, and message do not match.
	ErrInvalidSignature = errors.New("invalid signature")
)

const idSeparator = "/"

func splitID(id string) []string {
	return strings.Split(strings.Trim(id, idSeparator), idSeparator)
}

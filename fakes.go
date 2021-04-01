package veil

import (
	"crypto/rand"
	"math/big"

	"github.com/codahale/veil/internal/r255"
)

// AddFakes adds n randomly-generated public keys to the given set of public keys, shuffles the
// results, and returns them. This allows senders of messages to conceal the true number of
// recipients of a particular message.
func AddFakes(keys []*PublicKey, n int) ([]*PublicKey, error) {
	// Make a copy of the public keys.
	out := make([]*PublicKey, len(keys), len(keys)+n)
	copy(out, keys)

	// Add n randomly generated keys to the end.
	for i := 0; i < n; i++ {
		_, pub, err := r255.NewEphemeralKeys()
		if err != nil {
			return nil, err
		}

		out = append(out, &PublicKey{k: pub})
	}

	// Shuffle the recipients. This will randomly distribute the N fake recipients throughout the
	// slice.
	if err := Shuffle(out); err != nil {
		return nil, err
	}

	return out, nil
}

// Shuffle performs an in-place Fisher-Yates shuffle, using crypto/rand to pick indexes.
func Shuffle(keys []*PublicKey) error {
	for i := len(keys) - 1; i > 0; i-- {
		// Randomly pick a card from the unshuffled deck.
		b, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}

		// Convert to a platform int.
		j := int(b.Int64())

		// Swap it with the current card.
		keys[i], keys[j] = keys[j], keys[i]
	}

	return nil
}

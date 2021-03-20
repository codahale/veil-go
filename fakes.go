package veil

import (
	crand "crypto/rand"
	"io"
	"math/big"
)

// AddFakes adds n randomly-generated public keys to the given set of public keys, shuffles the
// results, and returns them. This allows senders of messages to conceal the true number of
// recipients of a particular message.
func AddFakes(rand io.Reader, keys []*PublicKey, n int) ([]*PublicKey, error) {
	// Make a copy of the public keys.
	out := make([]*PublicKey, len(keys), len(keys)+n)
	copy(out, keys)

	// Add n randomly generated keys to the end.
	for i := 0; i < n; i++ {
		q, rk, _, err := generateKeys(rand)
		if err != nil {
			return nil, err
		}

		out = append(out, &PublicKey{
			q:  q,
			rk: rk,
		})
	}

	// Perform a Fisher-Yates shuffle, using crypto/rand to pick indexes. This will randomly
	// distribute the N fake recipients throughout the slice.
	for i := len(out) - 1; i > 0; i-- {
		// Randomly pick a card from the unshuffled deck.
		b, err := crand.Int(rand, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}

		// Convert to a platform int.
		j := int(b.Int64())

		// Swap it with the current card.
		out[i], out[j] = out[j], out[i]
	}

	return out, nil
}
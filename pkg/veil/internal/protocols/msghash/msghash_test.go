package msghash

import (
	"encoding/hex"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSplitWrites(t *testing.T) {
	t.Parallel()

	w1 := NewWriter(32)
	_, _ = io.WriteString(w1, "ok then")

	w2 := NewWriter(32)
	_, _ = io.WriteString(w2, "ok")
	_, _ = io.WriteString(w2, " then")

	assert.Equal(t, "digests", w1.Digest(), w2.Digest())
}

func TestWriter_Digest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		digestSize int
		input      string
		digest     string
	}{
		{
			name:       "regular",
			digestSize: 16,
			input:      "well this is a pickle",
			digest:     "b2da9f112e4939190e07e6fabb513489",
		},
		{
			name:       "regular plus one",
			digestSize: 16,
			input:      "well this is a pickle!",
			digest:     "226fb31c1e830fa2d7deaad344e3a572",
		},
		{
			name:       "double",
			digestSize: 32,
			input:      "well this is a pickle",
			digest:     "bd50df225eb914397f7437120ce5ea13e377d299b9eb86b451d713be5c2eb549",
		},
	}
	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w := NewWriter(test.digestSize)
			if _, err := io.WriteString(w, test.input); err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, "digest", test.digest, hex.EncodeToString(w.Digest()))
		})
	}
}

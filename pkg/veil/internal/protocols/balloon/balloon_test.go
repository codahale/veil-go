package balloon

import (
	"encoding/base64"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		passphrase  []byte
		salt        []byte
		space, time uint32
		size        int
		hash        string
	}{
		{
			name:       "baseline",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "qMWJLw8x419dmC0UzPSGlyO7RxYwEWdcQmYmCf0YoSw",
		},
		{
			name:       "different password",
			passphrase: []byte("toothsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "q0WOFmuP6vfGWDqbnI1Z/8DTr+42v0bKD24MeJkHy4M",
		},
		{
			name:       "different salt",
			passphrase: []byte("handsome"),
			salt:       []byte("grungy"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "iwNw66wRbzOTse8JwVWu9zaYx0zwYXkL5CZD2wCvdTE",
		},
		{
			name:       "different space",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      2048,
			time:       64,
			size:       32,
			hash:       "6sN3C9D6rBvSBXuQ7F+arGivWPniT3ZK0C9yvvnVPZQ",
		},
		{
			name:       "different time",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       96,
			size:       32,
			hash:       "0eEf1SB2XXtgyK+pqiEcrsWk5N936cmNWXCxeuTkF2Q",
		},
		{
			name:       "different size",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       16,
			hash:       "hWpgDD6tRNFXlX+ZYfKn8g",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			h := Hash(test.passphrase, test.salt, test.space, test.time, test.size)

			assert.Equal(t, "hash", test.hash, base64.RawStdEncoding.EncodeToString(h))
		})
	}
}

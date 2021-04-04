package balloonkdf

import (
	"encoding/hex"
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
			hash:       "7fe92438e87b2638f6094dbad5723f86e4b5de8682719e242283e8437cdf2044",
		},
		{
			name:       "different password",
			passphrase: []byte("toothsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "41d43f3a583018bb9ae14700b6ea00721338709635172c42825161fd3b895bb2",
		},
		{
			name:       "different salt",
			passphrase: []byte("handsome"),
			salt:       []byte("grungy"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "3708d65d2907466d70f06d89168fcb57069ec518c149dbec85e11a3e203f8811",
		},
		{
			name:       "different space",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      2048,
			time:       64,
			size:       32,
			hash:       "dd9d96f3740a6b4f1d59da231c47fcd50a9dc2073b08b3a29690dec31c4cb530",
		},
		{
			name:       "different time",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       96,
			size:       32,
			hash:       "3948a0af908f461aaab22204fe0f9f16602533a1b65667887b43a33f1993f1ea",
		},
		{
			name:       "different size",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       16,
			hash:       "eb6cbbb84199f5c11cd5f6562dcf8528",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			h := DeriveKey(test.passphrase, test.salt, test.space, test.time, test.size)

			assert.Equal(t, "hash", test.hash, hex.EncodeToString(h))
		})
	}
}

package balloon

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
			hash:       "a8d92e751b0a66c265689c2bb54b2b49066d255b47be39d7049ca2a79f5b68bf",
		},
		{
			name:       "different password",
			passphrase: []byte("toothsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "9bfd33200858fab4a204621f1b32a6ca75fc94b81fe8c81eb9eec0f69f264417",
		},
		{
			name:       "different salt",
			passphrase: []byte("handsome"),
			salt:       []byte("grungy"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "03a524ef3583d65d88947019f24b21fbe291b153c1a212faff4665ec4bc40474",
		},
		{
			name:       "different space",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      2048,
			time:       64,
			size:       32,
			hash:       "93daf67092ea0100e301fef60529e4401d896c410178a87359ed8b0200a86bcf",
		},
		{
			name:       "different time",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       96,
			size:       32,
			hash:       "12dfc0c3ebc4988d64b0f1f159e97bf1f88e77b623b9228edd8fea743843485c",
		},
		{
			name:       "different size",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       16,
			hash:       "1c0c28ea22c70773863b48ae5ce436f8",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			h := Hash(test.passphrase, test.salt, test.space, test.time, test.size)

			assert.Equal(t, "hash", test.hash, hex.EncodeToString(h))
		})
	}
}

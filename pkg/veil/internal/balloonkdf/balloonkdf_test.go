package balloonkdf

import (
	"encoding/hex"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		passphrase        []byte
		salt              []byte
		space, time, size int
		hash              string
	}{
		{
			name:       "baseline",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "943559d295f98ff5fa8c54764f87adf4d6867eebce369888f289af43f6bfc410",
		},
		{
			name:       "different password",
			passphrase: []byte("toothsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "377936ec0fb2bea703ab559eeafcf80b64973626dcea965a8bcbba30bd51a83a",
		},
		{
			name:       "different salt",
			passphrase: []byte("handsome"),
			salt:       []byte("grungy"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "fe8dd9dc347c508c416e56ca03cccc809c29434823fe765046e7875508cc623e",
		},
		{
			name:       "different space",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      2048,
			time:       64,
			size:       32,
			hash:       "4c4a52f7406673826726ef5cb0d9f636bdf2f080666f50aa59833f77ce982625",
		},
		{
			name:       "different time",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       96,
			size:       32,
			hash:       "ddc16d80d2011bdf2f9074be39927e3dc66a0d4b805952e8fd05c15413461c8e",
		},
		{
			name:       "different size",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       16,
			hash:       "61e235f832ccbc6a45940dd2ee55dea6",
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

func BenchmarkDeriveKey(b *testing.B) {
	passphrase := []byte("this is not a strong passphrase")
	salt := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		_ = DeriveKey(passphrase, salt, 1024, 16, 32)
	}
}

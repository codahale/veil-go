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
			hash:       "7b0fb95ace7261e41e9aa0efd1003edf3fbf16203b200e556ed177f6ee8ce757",
		},
		{
			name:       "different password",
			passphrase: []byte("toothsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "edeb47b981cc14052f85597a17740c91254f6021aa1781f42d8426b583150e5a",
		},
		{
			name:       "different salt",
			passphrase: []byte("handsome"),
			salt:       []byte("grungy"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "bb3874383a89853501e589868ad494cdd506df55523ca65967dfa972bedb1f6f",
		},
		{
			name:       "different space",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      2048,
			time:       64,
			size:       32,
			hash:       "23ed4722507eb883c34909e45dc5046534f15126ab420ae250e594757c18eeee",
		},
		{
			name:       "different time",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       96,
			size:       32,
			hash:       "c153e9c73ccf6523bb3bcc9dc8245fa8e7cf1a04e0856c082d8f11ace72be31d",
		},
		{
			name:       "different size",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       16,
			hash:       "1760956afa414b2de6cef9c78fd3066d",
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

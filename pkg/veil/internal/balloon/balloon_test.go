package balloon

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
			hash:       "7e18fb9dd47869a7fc0fca4a860a03bfa0913852d41f71a6bae3b0a7e5bdb448",
		},
		{
			name:       "different password",
			passphrase: []byte("toothsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "3eb77960ac52a150e09ea736dd4bd9f75ef51f11d0e20f04030c8b22ca5f7845",
		},
		{
			name:       "different salt",
			passphrase: []byte("handsome"),
			salt:       []byte("grungy"),
			space:      1024,
			time:       64,
			size:       32,
			hash:       "c478be6c6239d884d3bae1fdd49f1d760b65146c0374fad04e27a1bd7db91de0",
		},
		{
			name:       "different space",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      2048,
			time:       64,
			size:       32,
			hash:       "138b2ab50433b91c9285b986201bb8cb2dd6030be981f537d1c575b5e4010a85",
		},
		{
			name:       "different time",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       96,
			size:       32,
			hash:       "ff0896e889f2dc617f0a5a947ba045c542a51cb71738016392abca70591761d2",
		},
		{
			name:       "different size",
			passphrase: []byte("handsome"),
			salt:       []byte("random"),
			space:      1024,
			time:       64,
			size:       16,
			hash:       "3348426011dd3c9dc39aed86b17094d0",
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

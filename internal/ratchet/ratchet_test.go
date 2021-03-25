package ratchet

import (
	"encoding/hex"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestKeyRatchet(t *testing.T) {
	t.Parallel()

	var keys []string

	kr := New([]byte("this is ok"), 16)

	for i := 0; i < 4; i++ {
		key := kr.Next(i == 3)

		keys = append(keys, hex.EncodeToString(key))
	}

	assert.Equal(t, "keys", []string{
		"1f2b62f56528323e109234ed2416b937",
		"df0ae6cc6d6e2e9285402c71cd75d34f",
		"c6319c3278890a6a068b7a0382b872be",
		"d488195713ff46b665a7dfc49b79a0f7",
	}, keys)
}

func BenchmarkKeyRatchet(b *testing.B) {
	kr := New([]byte("this is ok"), 48)

	for i := 0; i < b.N; i++ {
		_ = kr.Next(false)
	}
}

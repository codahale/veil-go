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
		"14d195c0516c827e634ae01d597bbf89",
		"d726b635a43ae6d1c8f336bc91c0e2ac",
		"39b0bdf24cba1018de94b6d4ca43d640",
		"c94d06eb90587d00a38dcfeae887607c",
	}, keys)
}

func BenchmarkKeyRatchet(b *testing.B) {
	kr := New([]byte("this is ok"), 48)

	for i := 0; i < b.N; i++ {
		_ = kr.Next(false)
	}
}

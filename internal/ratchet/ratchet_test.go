package ratchet

import (
	"encoding/hex"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSequence_Next(t *testing.T) {
	t.Parallel()

	var keys []string

	kr := New([]byte("this is ok"), 16)

	for i := 0; i < 4; i++ {
		key := kr.Next(i == 3)

		keys = append(keys, hex.EncodeToString(key))
	}

	assert.Equal(t, "keys", []string{
		"af1227e20adee7a7ea44ce5e6889fa07",
		"13f3ac089cfcf98469b966a46cb66de8",
		"fcf535968bbefef4826ee5c06dc34226",
		"00cf8029c2a3f5bd248f27a06ae7988f",
	}, keys)
}

func BenchmarkSequence_Next(b *testing.B) {
	kr := New([]byte("this is ok"), 48)

	for i := 0; i < b.N; i++ {
		_ = kr.Next(false)
	}
}

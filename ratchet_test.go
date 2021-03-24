package veil

import (
	"encoding/hex"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestKeyRatchet(t *testing.T) {
	t.Parallel()

	var keys, ivs []string

	kr := newKeyRatchet([]byte("this is ok"))

	for i := 0; i < 4; i++ {
		key, iv := kr.ratchet(i == 3)

		keys = append(keys, hex.EncodeToString(key))
		ivs = append(ivs, hex.EncodeToString(iv))
	}

	assert.Equal(t, "keys", []string{
		"7ffa7f1149a3156f28af2423c7a66852f5ff086d15e3de6c53c7d8aef8680311",
		"dbd75bf7ca8961c5c47bcd5e44e4748e9ce9e52e815d940f52ed7f21cde2b126",
		"da37c04721c7b6c92295f58aedfc05a7c5b230ee5c8b9a0a89f6293b377c582a",
		"7f379cebbade226584a3b68bdca0f61683f6a1109f23f8d0898c1c2ec4a42b4c",
	}, keys)

	assert.Equal(t, "ivs", []string{
		"5eb00f793b874952cfb00787561d9376",
		"11f17942d12d9891eb3e7299d9d6da3a",
		"862e4b53aaa530266f17e558d1e92c97",
		"bef016c9481c88759f664e5987b51725",
	}, ivs)
}

func BenchmarkKeyRatchet(b *testing.B) {
	kr := newKeyRatchet([]byte("this is ok"))

	for i := 0; i < b.N; i++ {
		_, _ = kr.ratchet(false)
	}
}

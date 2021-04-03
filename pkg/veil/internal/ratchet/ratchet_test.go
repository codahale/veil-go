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
		"2e24c6695cc5a33d5ccd95ea3840a254",
		"a962a3d204ec244d0a91cc3deb25bbbe",
		"27dc9c75d4470f36bd37b926d9508bc8",
		"bea653ab34fb8e21f4407d28a354acac",
	}, keys)
}

func TestSequence_NextFinal(t *testing.T) {
	t.Parallel()

	var keys []string

	kr := New([]byte("this is ok"), 16)

	for i := 0; i < 5; i++ {
		key := kr.Next(i == 4)

		keys = append(keys, hex.EncodeToString(key))
	}

	assert.Equal(t, "keys", []string{
		"2e24c6695cc5a33d5ccd95ea3840a254",
		"a962a3d204ec244d0a91cc3deb25bbbe",
		"27dc9c75d4470f36bd37b926d9508bc8",
		"255e2227796aafba1fcfc1ce7eb30dcb",
		"e7d74e6ba3a3644f15d66f3e133d67ee",
	}, keys)
}

func BenchmarkSequence_Next(b *testing.B) {
	kr := New([]byte("this is ok"), 48)

	for i := 0; i < b.N; i++ {
		_ = kr.Next(false)
	}
}

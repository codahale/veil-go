package veil

import (
	"encoding/base64"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestKeyRatchet(t *testing.T) {
	t.Parallel()

	var keys, ivs []string

	kr := newKeyRatchet([]byte("this is ok"))

	for i := 0; i < 4; i++ {
		key, iv := kr.ratchet(i == 3)

		keys = append(keys, base64.RawURLEncoding.EncodeToString(key))
		ivs = append(ivs, base64.RawURLEncoding.EncodeToString(iv))
	}

	assert.Equal(t, "keys", []string{
		"Hyti9WUoMj4QkjTtJBa5N756CZZzelf5hRNEURdfra8",
		"3wrmzG1uLpKFQCxxzXXTTx6eC2Vtj46kxfL8ronVMRs",
		"xjGcMniJCmoGi3oDgrhyvmQ5123bYzpbvv73_6DIJC0",
		"1IgZVxP_RrZlp9_Em3mg9x3KzYWr6pYYhe47yoFYeKc",
	}, keys)

	assert.Equal(t, "ivs", []string{
		"YwbssehnDjw8mQjci1Vh1g",
		"DiiANgrLqYizT6W3FvFmYQ",
		"G4S_mkpVzWEiEpAwxlnSSA",
		"o0Sy6CDdfTmreHFkQy9Zmw",
	}, ivs)
}

func BenchmarkKeyRatchet(b *testing.B) {
	kr := newKeyRatchet([]byte("this is ok"))

	for i := 0; i < b.N; i++ {
		_, _ = kr.ratchet(false)
	}
}

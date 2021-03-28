package veil

import (
	"bytes"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestAddFakes(t *testing.T) {
	t.Parallel()

	alice, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	bob, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	all, err := AddFakes([]PublicKey{alice.PublicKey(), bob.PublicKey()}, 20)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "total count", 22, len(all))

	alices, bobs, others := 0, 0, 0

	for _, pk := range all {
		switch {
		case bytes.Equal(pk, alice.PublicKey()):
			alices++
		case bytes.Equal(pk, bob.PublicKey()):
			bobs++
		default:
			others++
		}
	}

	assert.Equal(t, "alice count", 1, alices)
	assert.Equal(t, "bob count", 1, bobs)
	assert.Equal(t, "other count", 20, others)
}

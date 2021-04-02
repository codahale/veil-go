package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestAddFakes(t *testing.T) {
	t.Parallel()

	alice, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	bea, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	all, err := AddFakes([]*PublicKey{alice.PublicKey("one"), bea.PublicKey("one")}, 20)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "total count", 22, len(all))

	alices, beas, others := 0, 0, 0

	for _, pk := range all {
		switch pk.String() {
		case alice.PublicKey("one").String():
			alices++
		case bea.PublicKey("one").String():
			beas++
		default:
			others++
		}
	}

	assert.Equal(t, "alice count", 1, alices)
	assert.Equal(t, "bea count", 1, beas)
	assert.Equal(t, "other count", 20, others)
}

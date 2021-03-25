package kem

import (
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/internal/xdh"
)

func TestExchange(t *testing.T) {
	t.Parallel()

	pkA, _, skA, err := xdh.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	pkB, _, skB, err := xdh.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	rkW, secretA, err := Send(&skA, &pkA, &pkB, []byte("boop"), 20)
	if err != nil {
		t.Fatal(err)
	}

	secretB := Receive(&skB, &pkB, &pkA, rkW, []byte("boop"), 20)

	assert.Equal(t, "derived secrets", secretA, secretB)
}

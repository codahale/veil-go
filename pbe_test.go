package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPBE(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	esk, err := EncryptSecretKey(sk, []byte("this is magic"), nil)
	if err != nil {
		t.Fatal(err)
	}

	dsk, err := DecryptSecretKey(esk, []byte("this is magic"))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted secret key", sk, dsk)
}

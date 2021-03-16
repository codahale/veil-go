package veil

import (
	"crypto/rand"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPBE(t *testing.T) {
	t.Parallel()

	kp, err := NewSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ekp, err := NewEncryptedSecretKey(rand.Reader, kp, []byte("this is magic"))
	if err != nil {
		t.Fatal(err)
	}

	dkp, err := ekp.Decrypt([]byte("this is magic"))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted keypair", kp.q.Bytes(), dkp.q.Bytes())
}

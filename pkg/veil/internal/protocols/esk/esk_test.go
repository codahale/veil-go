package esk

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	sk := []byte("welcome to the jungle")

	esk := Encrypt(key, sk, 16)

	dsk, err := Decrypt(key, esk, 16)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted secret key", sk, dsk)
}

func TestKeyMismatch(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	sk := []byte("welcome to the jungle")

	esk := Encrypt(key, sk, 16)

	if _, err := Decrypt([]byte("ok well no then"), esk, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestCiphertextModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	sk := []byte("welcome to the jungle")

	esk := Encrypt(key, sk, 16)

	esk[0] ^= 1

	if _, err := Decrypt(key, esk, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

func TestTagModification(t *testing.T) {
	t.Parallel()

	key := []byte("this is a good time")
	sk := []byte("welcome to the jungle")

	esk := Encrypt(key, sk, 16)

	esk[len(esk)-1] ^= 1

	if _, err := Decrypt(key, esk, 16); err == nil {
		t.Fatal("should not have decrypted")
	}
}

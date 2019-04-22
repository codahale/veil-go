package veil

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func TestPBE(t *testing.T) {
	kp, err := NewKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ekp, err := NewEncryptedKeyPair(rand.Reader, kp, []byte("this is magic"))
	if err != nil {
		t.Fatal(err)
	}

	dkp, err := ekp.Decrypt([]byte("this is magic"))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(kp, dkp) {
		t.Errorf("Expected %#v, but was %#v", kp, dkp)
	}
}

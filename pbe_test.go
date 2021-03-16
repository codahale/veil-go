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

func TestEncryptedSecretKey_MarshalBinary(t *testing.T) {
	t.Parallel()

	ekp := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Time:       10,
		Memory:     200,
		Threads:    30,
	}

	data, err := ekp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "encoded keypair",
		[]byte{
			0x00, 0x00, 0x04, 0x73, 0x61, 0x6c, 0x74, 0x00, 0x00, 0x0a, 0x63, 0x69, 0x70, 0x68,
			0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xc8,
			0x1e,
		},
		data)
}

func TestEncryptedSecretKey_UnmarshalBinary(t *testing.T) {
	t.Parallel()

	data := []byte{
		0x00, 0x00, 0x04, 0x73, 0x61, 0x6c, 0x74, 0x00, 0x00, 0x0a, 0x63, 0x69, 0x70, 0x68,
		0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xc8,
		0x1e,
	}
	want := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Time:       10,
		Memory:     200,
		Threads:    30,
	}
	got := &EncryptedSecretKey{}

	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshaled value", want, got)
}

func TestEncryptedSecretKey_MarshalText(t *testing.T) {
	t.Parallel()

	ekp := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Time:       10,
		Memory:     200,
		Threads:    30,
	}

	text, err := ekp.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "encoded keypair", []byte("AAAEc2FsdAAACmNpcGhlcnRleHQAAAAKAAAAyB4"), text)
}

func TestEncryptedSecretKey_UnmarshalText(t *testing.T) {
	t.Parallel()

	text := []byte("AAAEc2FsdAAACmNpcGhlcnRleHQAAAAKAAAAyB4")
	want := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Time:       10,
		Memory:     200,
		Threads:    30,
	}
	got := &EncryptedSecretKey{}

	if err := got.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshaled value", want, got)
}

func TestEncryptedSecretKey_String(t *testing.T) {
	t.Parallel()

	ekp := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Time:       10,
		Memory:     200,
		Threads:    30,
	}

	assert.Equal(t, "encoded keypair", "AAAEc2FsdAAACmNpcGhlcnRleHQAAAAKAAAAyB4", ekp.String())
}

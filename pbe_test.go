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

	esk, err := NewEncryptedSecretKey(sk, []byte("this is magic"), nil)
	if err != nil {
		t.Fatal(err)
	}

	dsk, err := esk.Decrypt([]byte("this is magic"))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "decrypted secret key", sk.s.Bytes(), dsk.s.Bytes())
	assert.Equal(t, "decrypted public key", sk.pk.q.Bytes(), dsk.pk.q.Bytes())
	assert.Equal(t, "decrypted public key representative", sk.pk.rk, dsk.pk.rk)
}

func TestEncryptedSecretKey_MarshalBinary(t *testing.T) {
	t.Parallel()

	esk := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Argon2idParams: Argon2idParams{
			Time:        10,
			Memory:      200,
			Parallelism: 30,
		},
	}

	data, err := esk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "encoded keypair",
		[]byte{
			0x04, 0x73, 0x61, 0x6c, 0x74, 0x00, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74,
			0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xc8, 0x1e,
		},
		data)
}

func TestEncryptedSecretKey_UnmarshalBinary(t *testing.T) {
	t.Parallel()

	data := []byte{
		0x04, 0x73, 0x61, 0x6c, 0x74, 0x00, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65,
		0x78, 0x74, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xc8, 0x1e,
	}
	want := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Argon2idParams: Argon2idParams{
			Time:        10,
			Memory:      200,
			Parallelism: 30,
		},
	}
	got := &EncryptedSecretKey{}

	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshaled value", want, got)
}

func TestEncryptedSecretKey_MarshalText(t *testing.T) {
	t.Parallel()

	esk := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Argon2idParams: Argon2idParams{
			Time:        10,
			Memory:      200,
			Parallelism: 30,
		},
	}

	text, err := esk.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "encoded keypair", "BHNhbHQACmNpcGhlcnRleHQAAAAKAAAAyB4", string(text))
}

func TestEncryptedSecretKey_UnmarshalText(t *testing.T) {
	t.Parallel()

	text := []byte("BHNhbHQACmNpcGhlcnRleHQAAAAKAAAAyB4")
	want := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Argon2idParams: Argon2idParams{
			Time:        10,
			Memory:      200,
			Parallelism: 30,
		},
	}
	got := &EncryptedSecretKey{}

	if err := got.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshaled value", want, got)
}

func TestEncryptedSecretKey_String(t *testing.T) {
	t.Parallel()

	esk := &EncryptedSecretKey{
		Salt:       []byte("salt"),
		Ciphertext: []byte("ciphertext"),
		Argon2idParams: Argon2idParams{
			Time:        10,
			Memory:      200,
			Parallelism: 30,
		},
	}

	assert.Equal(t, "encoded keypair", "BHNhbHQACmNpcGhlcnRleHQAAAAKAAAAyB4", esk.String())
}

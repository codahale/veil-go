package veil

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/internal/xdh"
)

func TestPublicKey_Text(t *testing.T) {
	t.Parallel()

	pk := PublicKey{}
	pk2 := PublicKey{}

	// Make a fake, constant public key.
	pk.q.Derive([]byte("ok yeah"))

	// Re-derive the representative.
	pk.rk = xdh.PublicToRepresentative(&pk.q)

	j, err := json.Marshal(&pk)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "text representation",
		`"3H7PDhB1yaW_eNYMApqRRjWiO2PakBpodGNahRBmoBU"`, string(j))

	if err := json.Unmarshal(j, &pk2); err != nil {
		t.Fatal(err)
	}

	if !pk.q.Equals(&pk2.q) || !bytes.Equal(pk.rk, pk2.rk) {
		t.Error("bad round trip")
	}
}

func TestPublicKey_Binary(t *testing.T) {
	t.Parallel()

	pk := PublicKey{}
	pk2 := PublicKey{}
	buf := bytes.NewBuffer(nil)

	// Make a fake, constant public key.
	pk.q.Derive([]byte("ok yeah"))

	// Re-derive the representative.
	pk.rk = xdh.PublicToRepresentative(&pk.q)

	e := gob.NewEncoder(buf)
	if err := e.Encode(&pk); err != nil {
		t.Fatal(err)
	}

	d := gob.NewDecoder(buf)
	if err := d.Decode(&pk2); err != nil {
		t.Fatal(err)
	}

	if !pk.q.Equals(&pk2.q) || !bytes.Equal(pk.rk, pk2.rk) {
		t.Error("bad round trip")
	}
}

func TestSecretKey_String(t *testing.T) {
	t.Parallel()

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation", sk.PublicKey().String(), sk.String())
}

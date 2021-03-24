package veil

import (
	"encoding/hex"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestKeyRatchet(t *testing.T) {
	t.Parallel()

	var keys, nonces []string

	kr := newKeyRatchet([]byte("this is ok"))

	for i := 0; i < 4; i++ {
		key, nonce := kr.ratchet(i == 3)

		keys = append(keys, hex.EncodeToString(key))
		nonces = append(nonces, hex.EncodeToString(nonce))
	}

	assert.Equal(t, "keys", []string{
		"2637ed9f6fed1a6fdd9441d28f29ba2c15a0cfe0961b0a8e6776aaebbf194c80",
		"83ffb6613482f9a203b14ddf4857a8dff33c8f3f4f8bf6a1788a30ec2bf3ee8a",
		"ba32e763194056d45d65ee0625dd08ec2183f4fc57c92d619b89627948a00cd7",
		"1d530be366cb0a838528b7ca5e451d5d857840ba45f80748c6321c890937c832",
	}, keys)

	assert.Equal(t, "nonces", []string{
		"521c99f5e044a700dbeb5df9",
		"71d53847abefd510334bb373",
		"05a0a3c77491ba1d21e5571a",
		"5027419289a43760c661ef8f",
	}, nonces)
}

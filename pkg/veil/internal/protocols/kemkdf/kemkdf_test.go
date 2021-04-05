package kemkdf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
)

func TestDeriveKey(t *testing.T) {
	t.Parallel()

	zzE := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x04}, r255.SecretKeySize))
	zzS := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x49}, r255.SecretKeySize))
	pubE := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x88}, r255.SecretKeySize))
	pubR := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf1}, r255.SecretKeySize))
	pubS := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xd5}, r255.SecretKeySize))

	t.Run("header key", func(t *testing.T) {
		t.Parallel()

		key := DeriveKey(zzE, zzS, pubE, pubR, pubS, 16, true)

		assert.Equal(t, "derived header key",
			"7e621113e6d67b9749f2b99d261f4f01", hex.EncodeToString(key))
	})

	t.Run("message key", func(t *testing.T) {
		t.Parallel()

		key := DeriveKey(zzE, zzS, pubE, pubR, pubS, 16, false)

		assert.Equal(t, "derived header key",
			"55bf3ef5d8ba68112ac04d2213edb468", hex.EncodeToString(key))
	})
}

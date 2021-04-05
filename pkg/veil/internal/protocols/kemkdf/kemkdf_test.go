package kemkdf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/pkg/veil/internal/protocols/rng"
	"github.com/codahale/veil/pkg/veil/internal/r255"
	"github.com/gtank/ristretto255"
)

func TestDeriveKey(t *testing.T) {
	t.Parallel()

	zzE := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x04}, r255.UniformBytestringSize))
	zzS := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x49}, r255.UniformBytestringSize))
	pubE := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0x88}, r255.UniformBytestringSize))
	pubR := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf1}, r255.UniformBytestringSize))
	pubS := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xd5}, r255.UniformBytestringSize))

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

func TestExchange(t *testing.T) {
	t.Parallel()

	privA, pubA, err := rng.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	privB, pubB, err := rng.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}

	pkW, secretA, err := Send(privA, pubA, pubB, 20, true)
	if err != nil {
		t.Fatal(err)
	}

	secretB := Receive(privB, pubB, pubA, pkW, 20, true)

	assert.Equal(t, "derived secrets", secretA, secretB)
}

func BenchmarkSend(b *testing.B) {
	privA, pubA, err := rng.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	_, pubB, err := rng.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = Send(privA, pubA, pubB, 20, false)
	}
}

func BenchmarkReceive(b *testing.B) {
	privA, pubA, err := rng.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	privB, pubB, err := rng.NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	pkW, _, err := Send(privA, pubA, pubB, 20, false)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = Receive(privB, pubB, pubA, pkW, 20, false)
	}
}

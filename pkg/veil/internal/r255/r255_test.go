package r255

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestDiffieHellman(t *testing.T) {
	t.Parallel()

	skA, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	skB, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	xA := skA.PrivateKey("dh").DiffieHellman(skB.PublicKey("misc"))
	xB := skB.PrivateKey("misc").DiffieHellman(skA.PublicKey("dh"))

	assert.Equal(t, "shared secret", 1, xA.Equal(xB))
}

func TestDerivedKeys(t *testing.T) {
	t.Parallel()

	// Create a new secret key.
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	// Derive a key pair from the secret key.
	privA, pubA := sk.PrivateKey("one"), sk.PublicKey("one")

	// Derive another key pair in parallel.
	privB, pubB := privA.Derive("two"), pubA.Derive("two")

	// Calculate the public key for the final private key.
	pubBp := privB.PublicKey()

	assert.Equal(t, "derived keys", pubB.String(), pubBp.String())
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	message := []byte("ok bud")

	// Create a new secret key.
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	// Sign it with a private key derived from the secret key.
	sig := sk.PrivateKey("signing").Sign(message)

	// Verify it with a public key derived from the secret key.
	if sk.PublicKey("signing").Verify([]byte("other message"), sig) {
		t.Error("did verify")
	}

	// Test that the signature doesn't verify another message.
	if sk.PublicKey("signing").Verify([]byte("other message"), sig) {
		t.Error("did verify")
	}

	// Test that another public key doesn't verify the message.
	if sk.PublicKey("drawing").Verify([]byte("other message"), sig) {
		t.Error("did verify")
	}

	// Create a new secret key and test that the signature cannot be verified with its private key.
	sk2, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	if sk2.PublicKey("signing").Verify(message, sig) {
		t.Error("didn't verify")
	}
}

func TestPublicKey_Encode(t *testing.T) {
	t.Parallel()

	// Create a new secret key.
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	// Derive a public key.
	pk := sk.PublicKey("example")

	// Encode the public key.
	buf := pk.Encode(nil)

	// Decode it again.
	pk2, err := DecodePublicKey(buf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "public key", pk.String(), pk2.String())
}

func BenchmarkPrivateKey_DiffieHellman(b *testing.B) {
	priv, pub, err := NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = priv.DiffieHellman(pub)
	}
}

func BenchmarkPrivateKey_Derive(b *testing.B) {
	priv, _, err := NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = priv.Derive("label-example-text")
	}
}

func BenchmarkPrivateKey_Sign(b *testing.B) {
	priv, _, err := NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("an example message containing text")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = priv.Sign(message)
	}
}

func BenchmarkPublicKey_Verify(b *testing.B) {
	priv, pub, err := NewEphemeralKeys()
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("an example message containing text")
	sig := priv.Sign(message)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = pub.Verify(message, sig)
	}
}

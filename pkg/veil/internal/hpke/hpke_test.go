package hpke

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/codahale/gubbins/assert"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	plaintext := []byte("this is a welcome change from previous events")
	src := bytes.NewReader(plaintext)
	dst := bytes.NewBuffer(nil)

	qA := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf5}, internal.UniformBytestringSize))
	qB := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf5}, internal.UniformBytestringSize))
	qC := ristretto255.NewElement().FromUniformBytes(bytes.Repeat([]byte{0xf5}, internal.UniformBytestringSize))

	n, err := Encrypt(dst, src, dS, qS, []*ristretto255.Element{qR, qA, qB, qC}, 322)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(dst.Len()), n)

	src = bytes.NewReader(dst.Bytes())
	dst = bytes.NewBuffer(nil)

	n, err = Decrypt(dst, src, dR, qR, qS)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(dst.Len()), n)
	assert.Equal(t, "plaintext", plaintext, dst.Bytes())
}

func TestBadSender(t *testing.T) {
	t.Parallel()

	plaintext := []byte("this is a welcome change from previous events")
	src := bytes.NewReader(plaintext)
	dst := bytes.NewBuffer(nil)

	n, err := Encrypt(dst, src, dS, qS, []*ristretto255.Element{qR}, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(dst.Len()), n)

	src = bytes.NewReader(dst.Bytes())
	dst = bytes.NewBuffer(nil)

	n, err = Decrypt(dst, src, dR, qR, qR)

	assert.Equal(t, "written bytes", int64(0), n)
	assert.Equal(t, "error", ErrInvalidCiphertext, err, cmpopts.EquateErrors())
}

func TestBadRecipient(t *testing.T) {
	t.Parallel()

	plaintext := []byte("this is a welcome change from previous events")
	src := bytes.NewReader(plaintext)
	dst := bytes.NewBuffer(nil)

	n, err := Encrypt(dst, src, dS, qS, []*ristretto255.Element{qR}, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(dst.Len()), n)

	src = bytes.NewReader(dst.Bytes())
	dst = bytes.NewBuffer(nil)

	n, err = Decrypt(dst, src, dS, qS, qS)

	assert.Equal(t, "written bytes", int64(0), n)
	assert.Equal(t, "error", ErrInvalidCiphertext, err, cmpopts.EquateErrors())
}

func TestBadHeader(t *testing.T) {
	t.Parallel()

	plaintext := []byte("this is a welcome change from previous events")
	src := bytes.NewReader(plaintext)
	dst := bytes.NewBuffer(nil)

	n, err := Encrypt(dst, src, dS, qS, []*ristretto255.Element{qR}, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(dst.Len()), n)

	// Poison the header.
	ct := dst.Bytes()
	ct[len(ct)-internal.TagSize-3] ^= 1

	src = bytes.NewReader(ct)
	dst = bytes.NewBuffer(nil)

	_, err = Decrypt(dst, src, dR, qR, qS)

	assert.Equal(t, "error", ErrInvalidCiphertext, err, cmpopts.EquateErrors())
}

func TestBadTag(t *testing.T) {
	t.Parallel()

	plaintext := []byte("this is a welcome change from previous events")
	src := bytes.NewReader(plaintext)
	dst := bytes.NewBuffer(nil)

	n, err := Encrypt(dst, src, dS, qS, []*ristretto255.Element{qR}, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(dst.Len()), n)

	// Poison the header.
	ct := dst.Bytes()
	ct[len(ct)-3] ^= 1

	src = bytes.NewReader(ct)
	dst = bytes.NewBuffer(nil)

	_, err = Decrypt(dst, src, dR, qR, qS)

	assert.Equal(t, "error", ErrInvalidCiphertext, err, cmpopts.EquateErrors())
}

func TestBadCiphertext(t *testing.T) {
	t.Parallel()

	plaintext := []byte("this is a welcome change from previous events")
	src := bytes.NewReader(plaintext)
	dst := bytes.NewBuffer(nil)

	n, err := Encrypt(dst, src, dS, qS, []*ristretto255.Element{qR}, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(dst.Len()), n)

	// Poison the ciphertext.
	ct := dst.Bytes()
	ct[0] ^= 1

	src = bytes.NewReader(ct)
	dst = bytes.NewBuffer(nil)

	_, err = Decrypt(dst, src, dR, qR, qS)

	assert.Equal(t, "error", ErrInvalidCiphertext, err, cmpopts.EquateErrors())
}

func BenchmarkEncrypt(b *testing.B) {
	plaintext := make([]byte, 1024*1024)
	recipients := []*ristretto255.Element{qR, qS, qR, qS, qR, qS}

	for i := 0; i < b.N; i++ {
		_, err := Encrypt(io.Discard, bytes.NewReader(plaintext), dS, qS, recipients, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

//nolint:gochecknoglobals // constants
var (
	dS = ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x4f}, internal.UniformBytestringSize))
	qS = ristretto255.NewElement().ScalarBaseMult(dS)
	dR = ristretto255.NewScalar().FromUniformBytes(bytes.Repeat([]byte{0x22}, internal.UniformBytestringSize))
	qR = ristretto255.NewElement().ScalarBaseMult(dR)
)

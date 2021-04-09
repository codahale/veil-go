package armor

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestNewEncoder(t *testing.T) {
	t.Parallel()

	dst := bytes.NewBuffer(nil)

	enc, err := NewEncoder(dst)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := enc.Write(bytes.Repeat([]byte("hello world "), 12)); err != nil {
		t.Fatal()
	}

	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "armored output",
		strings.Join([]string{
			"-----BEGIN VEIL-----",
			"",
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
			"=6Mb8",
			"-----END VEIL-----",
		}, "\n"),
		dst.String())
}

func TestNewDecoder(t *testing.T) {
	t.Parallel()

	src := bytes.NewBufferString(
		strings.Join([]string{
			"-----BEGIN VEIL-----",
			"",
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
			"=6Mb8",
			"-----END VEIL-----",
		}, "\n"),
	)

	dec, err := NewDecoder(src)
	if err != nil {
		t.Fatal(err)
	}

	dst := bytes.NewBuffer(nil)
	if _, err := io.Copy(dst, dec); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "de-armored output", strings.Repeat("hello world ", 12), dst.String())
}

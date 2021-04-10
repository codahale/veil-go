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
	enc := NewEncoder(dst)

	if _, err := enc.Write(bytes.Repeat([]byte("hello world "), 12)); err != nil {
		t.Fatal()
	}

	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "armored output",
		strings.Join([]string{
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29y",
			"bGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8g",
			"d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
		}, "\n"),
		dst.String())
}

func TestNewDecoder(t *testing.T) {
	t.Parallel()

	src := bytes.NewBufferString(
		strings.Join([]string{
			"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29y",
			"bGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8g",
			"d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg",
		}, "\n"),
	)
	dec := NewDecoder(src)
	dst := bytes.NewBuffer(nil)

	if _, err := io.Copy(dst, dec); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "de-armored output", strings.Repeat("hello world ", 12), dst.String())
}

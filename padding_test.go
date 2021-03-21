package veil

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestPad(t *testing.T) {
	t.Parallel()

	s := "this is a value"

	padded, err := io.ReadAll(Pad(bytes.NewBufferString(s), 40))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "padded length", 55, len(padded))

	unpadded := bytes.NewBuffer(nil)

	n, err := io.Copy(Unpad(unpadded), bytes.NewReader(padded))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "written bytes", int64(len(padded)), n)
	assert.Equal(t, "unpadded value", s, unpadded.String())
}

package sigio

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestNewReader(t *testing.T) {
	t.Parallel()

	sig := bytes.Repeat([]byte{0xf0}, 32)
	src := append([]byte("well cool then explain this"), sig...)
	tr := NewReader(bytes.NewReader(src), 32)
	dst := bytes.NewBuffer(nil)

	n, err := io.Copy(dst, tr)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "bytes read", int64(27), n)
	assert.Equal(t, "read", "well cool then explain this", dst.String())
	assert.Equal(t, "signature", sig, tr.Signature)
}

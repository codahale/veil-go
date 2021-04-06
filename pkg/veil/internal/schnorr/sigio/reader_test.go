package sigio

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSignatureReader_Read(t *testing.T) {
	t.Parallel()

	src := []byte("well cool then explain thisAYE")
	tr := NewReader(bytes.NewReader(src), 3)
	dst := bytes.NewBuffer(nil)

	n, err := io.Copy(dst, tr)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "bytes read", int64(len(src)-3), n)
	assert.Equal(t, "read", src[:len(src)-3], dst.Bytes())
	assert.Equal(t, "signature", []byte("AYE"), tr.Signature)
}

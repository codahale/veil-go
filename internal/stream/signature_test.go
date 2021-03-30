package stream

import (
	"bytes"
	"crypto/sha512"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSignatureReader_Read(t *testing.T) {
	t.Parallel()

	h := sha512.New()
	src := []byte("well cool then explain thisAYE")
	tr := NewSignatureReader(bytes.NewReader(src), h, 3)
	dst := bytes.NewBuffer(nil)

	n, err := io.Copy(dst, tr)
	if err != nil {
		t.Fatal(err)
	}

	actualHash := tr.h.Sum(nil)
	expectedHash := sha512.Sum512(src[:len(src)-3])

	assert.Equal(t, "bytes read", int64(len(src)-3), n)
	assert.Equal(t, "read", src[:len(src)-3], dst.Bytes())
	assert.Equal(t, "hash", expectedHash[:], actualHash)
	assert.Equal(t, "signature", []byte("AYE"), tr.Signature)
}

package stream

import (
	"bytes"
	"crypto/sha512"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
	"github.com/codahale/veil/internal/xdh"
)

func TestSignatureReader_Read(t *testing.T) {
	t.Parallel()

	src := []byte("well cool then explain thisAYELLOWSUBMARINEAYELLOWSUBMARINEAYELLOWSUBMARINEAYELLOWSUBMARINE")
	tr := NewSignatureReader(bytes.NewReader(src))
	dst := bytes.NewBuffer(nil)

	n, err := io.Copy(dst, tr)
	if err != nil {
		t.Fatal(err)
	}

	actualHash := tr.SHA512.Sum(nil)
	expectedHash := sha512.Sum512(src[:len(src)-xdh.SignatureSize])

	assert.Equal(t, "bytes read", int64(len(src)-xdh.SignatureSize), n)
	assert.Equal(t, "read", src[:len(src)-xdh.SignatureSize], dst.Bytes())
	assert.Equal(t, "hash", expectedHash[:], actualHash)
	assert.Equal(t, "signature",
		[]byte("AYELLOWSUBMARINEAYELLOWSUBMARINEAYELLOWSUBMARINEAYELLOWSUBMARINE"), tr.Signature)
}

package msghash

import (
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestWriter_Digest(t *testing.T) {
	t.Parallel()

	w1 := NewWriter(32)
	_, _ = io.WriteString(w1, "ok then")

	w2 := NewWriter(32)
	_, _ = io.WriteString(w2, "ok")
	_, _ = io.WriteString(w2, " then")

	assert.Equal(t, "digests", w1.Digest(), w2.Digest())
}

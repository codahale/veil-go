package scopedhash

import (
	"crypto/sha512"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()

	sh := New("scope", sha512.New())
	_, _ = io.WriteString(sh, "message")
	digest := sh.Sum(nil)

	expected := sha512.Sum512([]byte("scopemessage"))
	assert.Equal(t, "scoped hash", expected[:], digest)
}

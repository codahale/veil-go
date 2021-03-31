package scopedhash

import (
	"encoding/base64"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestScopedHashing(t *testing.T) {
	t.Parallel()

	sh := newHash("scope")
	_, _ = io.WriteString(sh, "message")
	digest := sh.Sum(nil)

	assert.Equal(t, "scoped hash",
		"+9udT2FTL+URo4tJfUniia7ntr21ncKEsp15BLyBBFGc5eNndi5yaoEySOnPkFcOGgvWc7ZB/2oGqzC/7XX86Q",
		base64.RawStdEncoding.EncodeToString(digest))
}

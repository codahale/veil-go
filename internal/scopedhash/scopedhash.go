package scopedhash

import (
	"hash"
	"io"
)

func New(scope string, h hash.Hash) hash.Hash {
	_, _ = io.WriteString(h, scope)
	return h
}

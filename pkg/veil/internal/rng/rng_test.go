package rng

import (
	"io"
	"testing"
)

func TestReader_Read(t *testing.T) {
	t.Parallel()

	// Generate 10MiB and see if anything explodes.
	if _, err := io.CopyN(io.Discard, Reader, 1024*1024*10); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkRead(b *testing.B) {
	buf := make([]byte, 1024*1024)

	for i := 0; i < b.N; i++ {
		_, _ = Read(buf)
	}
}
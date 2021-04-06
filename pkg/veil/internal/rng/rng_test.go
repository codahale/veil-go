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

func TestIntN(t *testing.T) {
	t.Parallel()

	for i := 0; i < 10_000; i++ {
		j := IntN(10_000)
		if 0 > j || j >= 10_000 {
			t.Fatalf("%d is outside [0,10_000)", j)
		}
	}
}

func BenchmarkRead(b *testing.B) {
	buf := make([]byte, 1024*1024)

	for i := 0; i < b.N; i++ {
		_, _ = Read(buf)
	}
}

package streamio

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	// Constants.
	key := []byte("this is ok")
	ad := make([]byte, 19)

	// Set up inputs and outputs.
	src := bytes.NewBufferString("welcome to paradise")
	dst := bytes.NewBuffer(nil)

	// Create an AEAD writer.
	w := NewWriter(dst, key, ad, 9)

	// Encrypt the input.
	pn, err := io.Copy(w, src)
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to flush everything.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Check to see that we wrote the expected number of bytes.
	assert.Equal(t, "plaintext bytes written", int64(19), pn)
	assert.Equal(t, "ciphertext bytes written", (9+16)+(9+16)+(1+16), dst.Len())

	// Swap inputs and outputs.
	src = dst
	dst = bytes.NewBuffer(nil)

	// Create a reader.
	r := NewReader(src, key, ad, 9)

	// Decrypt the input.
	cn, err := io.Copy(dst, r)
	if err != nil {
		t.Fatal(err)
	}

	// Check to see that we read the expected number of bytes.
	assert.Equal(t, "plaintext bytes read", int64(19), cn)

	// Check to see that we decrypted the original message.
	assert.Equal(t, "plaintext", "welcome to paradise", dst.String())
}

//nolint:gocognit // It's just loops, guy.
func BenchmarkWriter(b *testing.B) {
	key := []byte("this is ok")
	ad := make([]byte, 19)
	sizes := []int64{100, 1_000, 10_000, 100_000, 1_000_000}

	for _, size := range sizes {
		size := size

		b.Run(fmt.Sprintf("%d bytes", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				w := NewWriter(io.Discard, key, ad, 64*1024)

				if _, err := io.CopyN(w, &fakeReader{}, size); err != nil {
					b.Fatal(err)
				}

				if err := w.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type fakeReader struct{}

func (f *fakeReader) Read(p []byte) (n int, err error) {
	return len(p), nil
}

var _ io.Reader = &fakeReader{}

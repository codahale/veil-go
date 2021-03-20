package veil

import (
	"bytes"
	"encoding/binary"
	"io"
)

// Pad returns an io.Reader which adds n bytes of random padding to the source io.Reader.
func Pad(src, rand io.Reader, n int) io.Reader {
	// Encode the number of random bytes into a buffer.
	buf := make([]byte, 4)
	n -= len(buf)
	binary.BigEndian.PutUint32(buf, uint32(n))

	// Return a multi-reader of the number of random bytes, the random bytes, and then the source.
	return io.MultiReader(bytes.NewReader(buf), io.LimitReader(rand, int64(n)), src)
}

// Unpad returns an io.Writer which will remove the random padding from incoming data before writing
// it to dst.
func Unpad(dst io.Writer) io.Writer {
	return &unpadWriter{
		dst:     dst,
		padding: -1,
	}
}

// unpadWriter encapsulates the state required to unpad writes to an io.Writer.
type unpadWriter struct {
	dst     io.Writer
	buf     []byte
	padding int
}

func (u *unpadWriter) Write(p []byte) (n int, err error) {
	// If we've already unpadded the input, write directly to dst.
	if u.padding == 0 {
		return u.dst.Write(p)
	}

	// If we have padding remaining to discard, handle that.
	if u.padding > 0 {
		// If this write is all padding, discard it.
		if len(p) <= u.padding {
			u.padding -= len(p)
			return len(p), err
		}

		// If this write is part padding, discard the padding and write the rest.
		n, err = u.dst.Write(p[u.padding:])
		n += u.padding
		u.padding = 0

		return n, err
	}

	// Append the current write to the buffered writes.
	u.buf = append(u.buf, p...)

	// If we have enough buffered bytes to parse the padding, do so and replay the buffered writes.
	if len(u.buf) >= 4 {
		u.padding = int(binary.BigEndian.Uint32(u.buf))

		n, err = u.Write(u.buf[4:])
		if err != nil {
			return n + 4, err
		}

		u.buf = nil
	}

	return len(p), nil
}

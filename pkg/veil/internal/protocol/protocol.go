package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/gtank/ristretto255"
	"github.com/sammyne/strobe"
)

type Protocol struct {
	s *strobe.Strobe
}

func New(name string) *Protocol {
	s, err := strobe.New(name, strobe.Bit256)
	if err != nil {
		panic(err)
	}

	return &Protocol{s: s}
}

func (p *Protocol) MetaAD(data []byte) {
	if err := p.s.AD(data, metaOpts); err != nil {
		panic(err)
	}
}

func (p *Protocol) AD(data []byte) {
	if err := p.s.AD(data, defaultOpts); err != nil {
		panic(err)
	}
}

func (p *Protocol) KEY(key []byte) {
	k := make([]byte, len(key))
	copy(k, key)

	if err := p.s.KEY(k, false); err != nil {
		panic(err)
	}
}

func (p *Protocol) KEYRand(n int) error {
	k := make([]byte, n)
	if _, err := rand.Read(k); err != nil {
		return err
	}

	if err := p.s.KEY(k, false); err != nil {
		panic(err)
	}

	return nil
}

func (p *Protocol) Ratchet() {
	// Setting L = sec/8 bytes is sufficient when R ≥ sec/8. That is, set L to 16 bytes or 32 bytes
	// for Strobe-128/b and Strobe-256/b, respectively.
	if err := p.s.RATCHET(int(strobe.Bit256) / 8); err != nil {
		panic(err)
	}
}

func (p *Protocol) PRF(dst []byte, n int) []byte {
	ret, out := internal.SliceForAppend(dst, n)

	if err := p.s.PRF(out, false); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) PRFScalar() *ristretto255.Scalar {
	var buf [internal.UniformBytestringSize]byte

	return ristretto255.NewScalar().FromUniformBytes(p.PRF(buf[:0], internal.UniformBytestringSize))
}

func (p *Protocol) SendENC(dst, plaintext []byte) []byte {
	ret, out := internal.SliceForAppend(dst, len(plaintext))
	copy(out, plaintext)

	if _, err := p.s.SendENC(out, defaultOpts); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) RecvENC(dst, ciphertext []byte) []byte {
	ret, out := internal.SliceForAppend(dst, len(ciphertext))
	copy(out, ciphertext)

	if _, err := p.s.RecvENC(out, defaultOpts); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) SendMAC(dst []byte) []byte {
	ret, out := internal.SliceForAppend(dst, internal.MACSize)

	if err := p.s.SendMAC(out, defaultOpts); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) RecvMAC(mac []byte) error {
	m := make([]byte, len(mac))
	copy(m, mac)

	return p.s.RecvMAC(m, defaultOpts)
}

func (p *Protocol) SendCLR(data []byte) {
	if err := p.s.SendCLR(data, defaultOpts); err != nil {
		panic(err)
	}
}

func (p *Protocol) RecvCLR(data []byte) {
	if err := p.s.RecvCLR(data, defaultOpts); err != nil {
		panic(err)
	}
}

func (p *Protocol) SendENCStream(dst io.Writer) io.Writer {
	p.SendENC(nil, nil)

	// Return a writer.
	return &callbackWriter{
		buf: make([]byte, 1024),
		callback: func(dst, b []byte) []byte {
			return p.moreSendENC(dst, b)
		},
		dst: dst,
	}
}

func (p *Protocol) RecvENCStream(dst io.Writer) io.Writer {
	p.RecvENC(nil, nil)

	// Return a writer.
	return &callbackWriter{
		buf: make([]byte, 1024),
		callback: func(dst, b []byte) []byte {
			return p.moreRecvENC(dst, b)
		},
		dst: dst,
	}
}

func (p *Protocol) RecvCLRStream(dst io.Writer) io.Writer {
	p.RecvCLR(nil)

	return &callbackWriter{
		callback: func(_, b []byte) []byte {
			p.moreRecvCLR(b)

			return b
		},
		dst: dst,
	}
}

func (p *Protocol) SendCLRStream(dst io.Writer) io.Writer {
	p.SendCLR(nil)

	return &callbackWriter{
		callback: func(_, b []byte) []byte {
			p.moreSendCLR(b)

			return b
		},
		dst: dst,
	}
}

func (p *Protocol) Clone() *Protocol {
	return &Protocol{s: p.s.Clone()}
}

func (p *Protocol) moreSendENC(dst, plaintext []byte) []byte {
	ret, out := internal.SliceForAppend(dst, len(plaintext))
	copy(out, plaintext)

	if _, err := p.s.SendENC(out, streamingOpts); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) moreRecvENC(dst, ciphertext []byte) []byte {
	ret, out := internal.SliceForAppend(dst, len(ciphertext))
	copy(out, ciphertext)

	if _, err := p.s.RecvENC(out, streamingOpts); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) moreSendCLR(data []byte) {
	if err := p.s.SendCLR(data, streamingOpts); err != nil {
		panic(err)
	}
}

func (p *Protocol) moreRecvCLR(data []byte) {
	if err := p.s.RecvCLR(data, streamingOpts); err != nil {
		panic(err)
	}
}

// LittleEndianU32 returns n as a 32-bit little endian bit string.
func LittleEndianU32(n int) []byte {
	var b [4]byte

	binary.LittleEndian.PutUint32(b[:], uint32(n))

	return b[:]
}

type callbackWriter struct {
	buf      []byte
	callback func([]byte, []byte) []byte
	dst      io.Writer
}

func (w *callbackWriter) Write(p []byte) (n int, err error) {
	w.buf = w.callback(w.buf[:0], p)
	return w.dst.Write(w.buf)
}

//nolint:gochecknoglobals // constants
var (
	defaultOpts   = &strobe.Options{}
	metaOpts      = &strobe.Options{Meta: true}
	streamingOpts = &strobe.Options{Streaming: true}
)

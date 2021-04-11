package protocol

import (
	"encoding/binary"

	"github.com/codahale/veil/pkg/veil/internal"
	"github.com/sammyne/strobe"
)

type Protocol struct {
	s *strobe.Strobe
}

type Option uint

const (
	Meta Option = iota + 1
	Streaming
)

func New(name string) *Protocol {
	s, err := strobe.New(name, strobe.Bit256)
	if err != nil {
		panic(err)
	}

	return &Protocol{s: s}
}

func (p *Protocol) AD(data []byte, opts ...Option) {
	if err := p.s.AD(data, toOpts(opts)); err != nil {
		panic(err)
	}
}

func (p *Protocol) Key(key []byte, opts ...Option) {
	k := make([]byte, len(key))
	copy(k, key)

	if err := p.s.KEY(k, toOpts(opts).Streaming); err != nil {
		panic(err)
	}
}

func (p *Protocol) PRF(b []byte, opts ...Option) {
	if err := p.s.PRF(b, toOpts(opts).Streaming); err != nil {
		panic(err)
	}
}

func (p *Protocol) SendENC(dst, plaintext []byte, opts ...Option) []byte {
	ret, out := internal.SliceForAppend(dst, len(plaintext))
	copy(out, plaintext)

	if _, err := p.s.SendENC(out, toOpts(opts)); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) RecvENC(dst, ciphertext []byte, opts ...Option) []byte {
	ret, out := internal.SliceForAppend(dst, len(ciphertext))
	copy(out, ciphertext)

	if _, err := p.s.RecvENC(out, toOpts(opts)); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) SendMAC(dst []byte, n int, opts ...Option) []byte {
	ret, out := internal.SliceForAppend(dst, n)

	if err := p.s.SendMAC(out, toOpts(opts)); err != nil {
		panic(err)
	}

	return ret
}

func (p *Protocol) RecvMAC(mac []byte, opts ...Option) error {
	m := make([]byte, len(mac))
	copy(m, mac)

	return p.s.RecvMAC(m, toOpts(opts))
}

func (p *Protocol) Ratchet() {
	//     Setting L = sec/8 bytes is sufficient when R ≥ sec/8. That is, set L to 16 bytes or 32
	//     bytes for Strobe-128/b and Strobe-256/b, respectively.
	if err := p.s.RATCHET(int(strobe.Bit256) / 8); err != nil {
		panic(err)
	}
}

func (p *Protocol) SendCLR(data []byte, opts ...Option) {
	if err := p.s.SendCLR(data, toOpts(opts)); err != nil {
		panic(err)
	}
}

func (p *Protocol) RecvCLR(data []byte, opts ...Option) {
	if err := p.s.RecvCLR(data, toOpts(opts)); err != nil {
		panic(err)
	}
}

func (p *Protocol) Clone() *Protocol {
	return &Protocol{
		s: p.s.Clone(),
	}
}

func toOpts(opts []Option) *strobe.Options {
	var o strobe.Options

	for _, opt := range opts {
		switch opt {
		case Streaming:
			o.Streaming = true
		case Meta:
			o.Meta = true
		}
	}

	return &o
}

// LittleEndianU32 returns n as a 32-bit little endian bit string.
func LittleEndianU32(n int) []byte {
	var b [4]byte

	binary.LittleEndian.PutUint32(b[:], uint32(n))

	return b[:]
}

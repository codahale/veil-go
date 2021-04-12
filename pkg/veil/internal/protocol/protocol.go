package protocol

import (
	"encoding/binary"

	"github.com/gtank/ristretto255"

	"github.com/codahale/veil/pkg/veil/internal"
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

func (p *Protocol) Ratchet() {
	// Setting L = sec/8 bytes is sufficient when R ≥ sec/8. That is, set L to 16 bytes or 32 bytes
	// for Strobe-128/b and Strobe-256/b, respectively.
	if err := p.s.RATCHET(int(strobe.Bit256) / 8); err != nil {
		panic(err)
	}
}

func (p *Protocol) PRF(b []byte) {
	if err := p.s.PRF(b, false); err != nil {
		panic(err)
	}
}

func (p *Protocol) PRFScalar() *ristretto255.Scalar {
	var buf [internal.UniformBytestringSize]byte

	p.PRF(buf[:])

	return ristretto255.NewScalar().FromUniformBytes(buf[:])
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

func (p *Protocol) SendMAC(dst []byte, n int) []byte {
	ret, out := internal.SliceForAppend(dst, n)

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

func (p *Protocol) MoreSendCLR(data []byte) {
	if err := p.s.SendCLR(data, streamingOpts); err != nil {
		panic(err)
	}
}

func (p *Protocol) MoreRecvCLR(data []byte) {
	if err := p.s.RecvCLR(data, streamingOpts); err != nil {
		panic(err)
	}
}

func (p *Protocol) Clone() *Protocol {
	return &Protocol{
		s: p.s.Clone(),
	}
}

// LittleEndianU32 returns n as a 32-bit little endian bit string.
func LittleEndianU32(n int) []byte {
	var b [4]byte

	binary.LittleEndian.PutUint32(b[:], uint32(n))

	return b[:]
}

//nolint:gochecknoglobals // constants
var (
	defaultOpts   = &strobe.Options{}
	metaOpts      = &strobe.Options{Meta: true}
	streamingOpts = &strobe.Options{Streaming: true}
)

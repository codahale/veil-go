package skid

import (
	"github.com/codahale/veil/pkg/veil/internal/protocols"
	"github.com/sammyne/strobe"
)

func ID(sk []byte, idSize int) []byte {
	s, err := strobe.New("veil.skid", strobe.Bit256)
	if err != nil {
		panic(err)
	}

	if err := s.AD(protocols.BigEndianU32(idSize), &strobe.Options{Meta: true}); err != nil {
		panic(err)
	}

	if err := s.AD(sk, &strobe.Options{}); err != nil {
		panic(err)
	}

	id := make([]byte, idSize)
	if err := s.PRF(id, false); err != nil {
		panic(err)
	}

	return id
}

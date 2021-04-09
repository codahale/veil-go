package veil

import (
	"testing"

	"github.com/codahale/gubbins/assert"
)

func TestSignature_MarshalText(t *testing.T) {
	t.Parallel()

	var s Signature
	if err := s.UnmarshalBinary([]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine")); err != nil {
		t.Fatal(err)
	}

	text, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "marshalled text",
		`2x2qUArEZSrxBKb7b5ojwG4hP3mTeKTzmuzrbZ7b9X9M75Zeq7nWzK2dwXXUZQp3KJvQyhX6vhP26M1GZFJgpxDA`,
		string(text))
}

func TestSignature_UnmarshalText(t *testing.T) {
	t.Parallel()

	var s Signature
	if err := s.UnmarshalText(
		[]byte(`2x2qUArEZSrxBKb7b5ojwG4hP3mTeKTzmuzrbZ7b9X9M75Zeq7nWzK2dwXXUZQp3KJvQyhX6vhP26M1GZFJgpxDA`),
	); err != nil {
		t.Fatal(err)
	}

	b, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "unmarshalled key",
		[]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine"), b)
}

func TestSignature_String(t *testing.T) {
	t.Parallel()

	var s Signature
	if err := s.UnmarshalBinary([]byte("ayellowsubmarineayellowsubmarineayellowsubmarineayellowsubmarine")); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "string representation",
		`2x2qUArEZSrxBKb7b5ojwG4hP3mTeKTzmuzrbZ7b9X9M75Zeq7nWzK2dwXXUZQp3KJvQyhX6vhP26M1GZFJgpxDA`,
		s.String())
}

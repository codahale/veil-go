package internal

import "testing"

func TestIntN(t *testing.T) {
	t.Parallel()

	for i := 0; i < 10_000; i++ {
		j := IntN(10_000)
		if 0 > j || j >= 10_000 {
			t.Fatalf("%d is outside [0,10_000)", j)
		}
	}
}

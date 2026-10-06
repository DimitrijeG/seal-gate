package cryptography

import "testing"

func TestGF256(t *testing.T) {
	t.Run("multiplying matches the FIPS 197 examples", func(t *testing.T) {
		// Known answers from FIPS 197, section 4.2.
		tests := []struct {
			name string
			a, b byte
			want byte
		}{
			{"0x57 times 0x83 is 0xc1", 0x57, 0x83, 0xc1},
			{"0x57 times 0x13 is 0xfe", 0x57, 0x13, 0xfe},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := gfMul(tt.a, tt.b); got != tt.want {
					t.Errorf("got %#x, want %#x", got, tt.want)
				}
			})
		}
	})

	t.Run("multiplying by zero gives zero and by one gives the same value", func(t *testing.T) {
		for i := range 256 {
			a := byte(i)
			if got := gfMul(a, 0); got != 0 {
				t.Errorf("gfMul(%#x, 0) = %#x, want 0", a, got)
			}
			if got := gfMul(a, 1); got != a {
				t.Errorf("gfMul(%#x, 1) = %#x, want %#x", a, got, a)
			}
		}
	})

	t.Run("every non-zero value times its inverse is one", func(t *testing.T) {
		for i := 1; i < 256; i++ {
			a := byte(i)
			if got := gfMul(a, gfInv(a)); got != 1 {
				t.Errorf("gfMul(%#x, gfInv(%#x)) = %#x, want 1", a, a, got)
			}
		}
	})

	t.Run("the inverse of zero is zero", func(t *testing.T) {
		if got := gfInv(0); got != 0 {
			t.Errorf("gfInv(0) = %#x, want 0", got)
		}
	})
}

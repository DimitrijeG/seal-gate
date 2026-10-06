package cryptography_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
)

var errShortRead = errors.New("fixedRandom: short read")

// fixedRandom returns preset bytes, so Split's output is a known answer.
type fixedRandom []byte

func (f fixedRandom) Bytes(n int) ([]byte, error) {
	if n > len(f) {
		return nil, errShortRead
	}
	return bytes.Clone(f[:n]), nil
}

// pick returns the shares at the given indexes, in that order.
func pick(shares [][]byte, idx ...int) [][]byte {
	picked := make([][]byte, len(idx))
	for i, j := range idx {
		picked[i] = shares[j]
	}
	return picked
}

func TestShamir(t *testing.T) {
	t.Run("split returns n shares, each one byte longer than the secret", func(t *testing.T) {
		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		secret := []byte("top secret")

		shares, err := s.Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		if len(shares) != 5 {
			t.Errorf("got %d shares, want %d", len(shares), 5)
		}

		for i, share := range shares {
			if len(share) != len(secret)+1 {
				t.Errorf("share %d: got %d bytes, want %d", i, len(share), len(secret)+1)
			}
		}
	})

	t.Run("split with a fixed random source returns known shares", func(t *testing.T) {
		// Each secret byte takes k-1 coefficients from random, lowest power first.
		tests := []struct {
			name   string
			random fixedRandom
			secret []byte
			k      int
			want   [][]byte
		}{
			{
				name:   "one-byte secret",
				random: fixedRandom{0x83},
				secret: []byte{0x42},
				k:      2,
				want:   [][]byte{{0xc1, 0x01}, {0x5f, 0x02}},
			},
			{
				name:   "two-byte secret takes one coeff per byte",
				random: fixedRandom{0x83, 0x10},
				secret: []byte{0x42, 0x01},
				k:      2,
				want:   [][]byte{{0xc1, 0x11, 0x01}, {0x5f, 0x21, 0x02}},
			},
			{
				name:   "coefficients are read lowest power first",
				random: fixedRandom{0x83, 0x10},
				secret: []byte{0x42},
				k:      3,
				want:   [][]byte{{0xd1, 0x01}, {0x1f, 0x02}, {0x8c, 0x03}},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s := cryptography.NewShamir(tt.random)

				shares, err := s.Split(tt.secret, len(tt.want), tt.k)
				if err != nil {
					t.Fatalf("Split: %v", err)
				}
				if len(shares) != len(tt.want) {
					t.Fatalf("got %d shares, want %d", len(shares), len(tt.want))
				}

				for i, want := range tt.want {
					if !bytes.Equal(shares[i], want) {
						t.Errorf("share %d: got %x, want %x", i, shares[i], want)
					}
				}
			})
		}
	})

	t.Run("split returns the random source's error", func(t *testing.T) {
		s := cryptography.NewShamir(fixedRandom{})
		_, err := s.Split([]byte("top secret"), 5, 3)
		if !errors.Is(err, errShortRead) {
			t.Errorf("got error %v, want %v", err, errShortRead)
		}
	})

	t.Run("combining known shares returns the known secret", func(t *testing.T) {
		// Shares of 0x42 under f(x) = 0x42 + 0x83·x, worked by hand.
		shares := [][]byte{{0xc1, 0x01}, {0x5f, 0x02}}
		s := cryptography.NewShamir(cryptography.CryptoRandom{})

		got, err := s.Combine(shares)
		if err != nil {
			t.Fatalf("Combine: %v", err)
		}

		if !bytes.Equal(got, []byte{0x42}) {
			t.Errorf("got %x, want %x", got, []byte{0x42})
		}
	})

	t.Run("combining all shares returns the secret", func(t *testing.T) {
		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		secret := []byte("top secret")

		shares, err := s.Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}

		got, err := s.Combine(shares)
		if err != nil {
			t.Fatalf("Combine: %v", err)
		}

		if !bytes.Equal(got, secret) {
			t.Errorf("got %x, want %x", got, secret)
		}
	})

	t.Run("no share contains the secret", func(t *testing.T) {
		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		secret := []byte("top secret")

		shares, err := s.Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}

		for i, share := range shares {
			if bytes.Contains(share, secret) {
				t.Errorf("share %d contains the secret", i)
			}
		}
	})

	t.Run("splitting the same secret twice gives different shares", func(t *testing.T) {
		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		secret := []byte("top secret")

		shares1, err := s.Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}

		shares2, err := s.Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}

		for i := range shares1 {
			if bytes.Equal(shares1[i], shares2[i]) {
				t.Errorf("share %d is the same in both splits", i)
			}
		}
	})

	t.Run("any threshold-sized subset returns the secret", func(t *testing.T) {
		tests := []struct {
			name   string
			subset []int
		}{
			{"the first three", []int{0, 1, 2}},
			{"the last three", []int{2, 3, 4}},
			{"every other share", []int{0, 2, 4}},
			{"shares out of order", []int{4, 0, 1}},
		}

		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		secret := []byte("top secret")

		shares, err := s.Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := s.Combine(pick(shares, tt.subset...))
				if err != nil {
					t.Fatalf("Combine: %v", err)
				}

				if !bytes.Equal(got, secret) {
					t.Errorf("got %x, want %x", got, secret)
				}
			})
		}
	})

	t.Run("fewer than threshold shares do not return the secret", func(t *testing.T) {
		r := cryptography.CryptoRandom{}
		s := cryptography.NewShamir(r)

		// Long enough that a chance match (256^-len) never happens.
		secret, err := r.Bytes(32)
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}

		shares, err := s.Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}

		got, err := s.Combine(shares[:2])
		if err != nil {
			t.Fatalf("Combine: %v", err)
		}

		if bytes.Equal(got, secret) {
			t.Errorf("recovered the secret from %d shares when the threshold is %d", 2, 3)
		}
	})

	t.Run("split rejects invalid parameters", func(t *testing.T) {
		tests := []struct {
			name   string
			secret []byte
			n      int
			k      int
		}{
			{"nil secret", nil, 5, 3},
			{"empty secret", []byte{}, 5, 3},
			{"zero threshold", []byte("top secret"), 5, 0},
			{"threshold of one", []byte("top secret"), 5, 1},
			{"threshold greater than number of shares", []byte("top secret"), 5, 6},
			{"too many shares", []byte("top secret"), 256, 3},
			{"negative number of shares", []byte("top secret"), -1, 3},
		}

		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := s.Split(tt.secret, tt.n, tt.k)
				if !errors.Is(err, cryptography.ErrInvalidSplit) {
					t.Errorf("got error %v, want %v", err, cryptography.ErrInvalidSplit)
				}
			})
		}
	})

	t.Run("split accepts the boundary parameters", func(t *testing.T) {
		tests := []struct {
			name   string
			secret []byte
			n      int
			k      int
		}{
			{"the smallest threshold and share count", []byte("top secret"), 2, 2},
			{"the largest share count, all of them needed", []byte("top secret"), 255, 255},
			{"a one-byte secret", []byte{0x01}, 5, 3},
		}

		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				shares, err := s.Split(tt.secret, tt.n, tt.k)
				if err != nil {
					t.Fatalf("Split: %v", err)
				}

				got, err := s.Combine(shares)
				if err != nil {
					t.Fatalf("Combine: %v", err)
				}

				if !bytes.Equal(got, tt.secret) {
					t.Errorf("got %x, want %x", got, tt.secret)
				}
			})
		}
	})

	t.Run("combine rejects invalid shares", func(t *testing.T) {
		tests := []struct {
			name   string
			shares [][]byte
		}{
			{"nil shares", nil},
			{"empty shares", [][]byte{}},
			{"one share", [][]byte{{0xc1, 0x01}}},
			{"nil share", [][]byte{nil, {0xc1, 0x01}}},
			{"a share with only the x byte", [][]byte{{0xc1, 0x01}, {0x02}}},
			{"shares of different lengths", [][]byte{{0xc1, 0x01}, {0x5f, 0xb3, 0x02}}},
			{"zero x in share", [][]byte{{0xc1, 0x01}, {0x5f, 0x00}}},
			{"duplicate x in share", [][]byte{{0xc1, 0x01}, {0x5f, 0x01}}},
		}

		s := cryptography.NewShamir(cryptography.CryptoRandom{})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := s.Combine(tt.shares)
				if !errors.Is(err, cryptography.ErrInvalidShares) {
					t.Errorf("got error %v, want %v", err, cryptography.ErrInvalidShares)
				}
			})
		}
	})
}

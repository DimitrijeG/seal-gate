package cryptography

import (
	"errors"
	"fmt"
	"slices"
)

// Random is the source of Split's polynomial coefficients.
type Random interface {
	Bytes(n int) ([]byte, error)
}

var (
	// ErrInvalidSplit is returned when Split's parameters cannot make valid shares.
	ErrInvalidSplit = errors.New("cryptography: invalid split parameters")
	// ErrInvalidShares is returned when Combine's shares cannot recover a secret.
	ErrInvalidShares = errors.New("cryptography: invalid shares")
)

// Shamir splits a secret into shares over GF(2^8), one polynomial per byte.
type Shamir struct {
	random Random
}

// NewShamir returns a Shamir that draws coefficients from random.
func NewShamir(random Random) *Shamir {
	return &Shamir{random: random}
}

// Split divides secret into n shares, any k of which recover it; each share is the y bytes followed by its x, 1..n.
func (s *Shamir) Split(secret []byte, n, k int) ([][]byte, error) {
	// Before Bytes: a bad k would make the length negative and panic.
	if len(secret) == 0 || k <= 1 || k > n || n > 255 {
		return nil, ErrInvalidSplit
	}

	coeffs, err := s.random.Bytes((k - 1) * len(secret))
	if err != nil {
		return nil, fmt.Errorf("cryptography: split: %w", err)
	}
	defer clear(coeffs)

	shares := make([][]byte, n)
	shareLen := len(secret) + 1
	for i := range n {
		x := byte(i + 1)

		shares[i] = make([]byte, shareLen)
		shares[i][shareLen-1] = x

		for j, b := range secret {
			// Byte j's coefficients are coeffs[j*(k-1):(j+1)*(k-1)], lowest power first;
			// Horner needs the highest first, so walk them backwards.
			var y byte
			for _, coeff := range slices.Backward(coeffs[j*(k-1) : (j+1)*(k-1)]) {
				y = gfMul(y, x) ^ coeff
			}
			shares[i][j] = gfMul(y, x) ^ b
		}
	}

	return shares, nil
}

// Combine recovers the secret from shares; with fewer than the threshold it returns wrong bytes, not an error.
func (s *Shamir) Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrInvalidShares
	}

	var seen [256]bool
	xs := make([]byte, len(shares))
	for i, share := range shares {
		if len(share) < 2 || len(share) != len(shares[0]) {
			return nil, ErrInvalidShares
		}

		x := share[len(share)-1]
		if x == 0 || seen[x] {
			return nil, ErrInvalidShares
		}
		seen[x] = true
		xs[i] = x
	}

	basis := make([]byte, len(shares))
	for i := range shares {
		p := byte(1)
		for j := range shares {
			if i == j {
				continue
			}
			p = gfMul(p, gfMul(xs[j], gfInv(xs[i]^xs[j])))
		}
		basis[i] = p
	}

	secret := make([]byte, len(shares[0])-1)
	for i, share := range shares {
		for b, y := range share[:len(share)-1] {
			secret[b] ^= gfMul(y, basis[i])
		}
	}

	return secret, nil
}

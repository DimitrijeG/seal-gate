package system

import (
	"bytes"
	"crypto/subtle"
)

// clearShares zeroes every share;
// clearing the outer slice alone would leave the bytes.
func clearShares(shares [][]byte) {
	for _, s := range shares {
		clear(s)
	}
}

// shareBuffer holds submitted shares until the threshold is reached.
type shareBuffer struct {
	shares [][]byte
}

func (b *shareBuffer) add(share []byte) {
	b.shares = append(b.shares, bytes.Clone(share))
}

// contains compares in constant time, so a caller cannot probe buffered bytes by timing.
func (b *shareBuffer) contains(share []byte) bool {
	for _, s := range b.shares {
		if subtle.ConstantTimeCompare(s, share) == 1 {
			return true
		}
	}
	return false
}

func (b *shareBuffer) len() int {
	return len(b.shares)
}

func (b *shareBuffer) clear() {
	clearShares(b.shares)
	b.shares = nil
}

// all returns the buffered shares themselves, not copies;
// callers must not retain or modify them.
func (b *shareBuffer) all() [][]byte {
	return b.shares
}

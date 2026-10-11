package cryptography

import "crypto/rand"

// CryptoRandom reads from crypto/rand, the operating system's secure source.
type CryptoRandom struct{}

var _ Random = CryptoRandom{}

func (CryptoRandom) Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

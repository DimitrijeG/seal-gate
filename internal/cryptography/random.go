package cryptography

import "crypto/rand"

type CryptoRandom struct{}

func (CryptoRandom) Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

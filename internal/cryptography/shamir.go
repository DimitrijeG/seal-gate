package cryptography

type Shamir struct{}

func NewShamir() *Shamir { return &Shamir{} }

func (s *Shamir) Split(secret []byte, n, k int) ([][]byte, error) {
	return nil, errNotImplemented
}

func (s *Shamir) Combine(shares [][]byte) ([]byte, error) {
	return nil, errNotImplemented
}

// Package barrier encrypts every value before it reaches storage and decrypts it on the way back, so no backend ever sees plaintext.
package barrier

import (
	"context"
	"errors"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

var ErrSealed = errors.New("barrier: sealed")
var errNotImplemented = errors.New("barrier: not implemented")

type AEADBarrier struct {
	physical storage.Backend
	keys     KeyProvider
	cipher   cryptography.Cipher
}

type KeyProvider interface {
	WithKey(func(k []byte) error) error
}

func NewAEADBarrier(physical storage.Backend, keys KeyProvider, cipher cryptography.Cipher) *AEADBarrier {
	return &AEADBarrier{physical: physical, keys: keys, cipher: cipher}
}

func (b *AEADBarrier) Put(ctx context.Context, key string, value []byte) error {
	return b.withKey(func(k []byte) error {
		return errNotImplemented
	})
}

func (b *AEADBarrier) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, b.withKey(func(k []byte) error {
		return errNotImplemented
	})
}

func (b *AEADBarrier) Delete(ctx context.Context, key string) error {
	return b.withKey(func(k []byte) error {
		return errNotImplemented
	})
}

// withKey maps a missing key to ErrSealed, whichever provider is wired in.
func (b *AEADBarrier) withKey(fn func(k []byte) error) error {
	err := b.keys.WithKey(fn)
	if errors.Is(err, cryptography.ErrNoActiveKey) {
		return ErrSealed
	}
	return err
}

func (b *AEADBarrier) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, errNotImplemented
}

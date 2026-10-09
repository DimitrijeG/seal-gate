// Package barrier encrypts every value before it reaches storage and decrypts it on the way back, so no backend ever sees plaintext.
package barrier

import (
	"context"
	"errors"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

var (
	ErrSealed             = errors.New("barrier: sealed")
	ErrUnsupportedVersion = errors.New("barrier: unsupported format version")
)

// valueFormatVersion prefixes every stored value; Get rejects any other version
// and binds the stored byte, not this constant, into the additional data.
const valueFormatVersion = 1

// AEADBarrier encrypts values with the barrier key before they reach the backend
// and refuses every operation while sealed.
type AEADBarrier struct {
	physical storage.Backend
	keys     KeyProvider
	cipher   cryptography.Cipher
}

// KeyProvider lends the barrier key for the duration of a callback;
// it returns cryptography.ErrNoActiveKey while sealed.
type KeyProvider interface {
	WithKey(func(barrierKey []byte) error) error
}

func NewAEADBarrier(physical storage.Backend, keys KeyProvider, cipher cryptography.Cipher) *AEADBarrier {
	return &AEADBarrier{physical: physical, keys: keys, cipher: cipher}
}

func (b *AEADBarrier) Put(ctx context.Context, key string, value []byte) error {
	return b.withKey(func(barrierKey []byte) error {
		ad := additionalData(valueFormatVersion, key)
		ciphertext, err := b.cipher.Encrypt(barrierKey, value, ad)
		if err != nil {
			return fmt.Errorf("barrier: %w", err)
		}

		stored := append([]byte{valueFormatVersion}, ciphertext...)
		if err := b.physical.Put(ctx, key, stored); err != nil {
			return fmt.Errorf("barrier: %w", err)
		}
		return nil
	})
}

func (b *AEADBarrier) Get(ctx context.Context, key string) ([]byte, error) {
	return withKeyValue(b, func(barrierKey []byte) ([]byte, error) {
		raw, err := b.physical.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("barrier: %w", err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("barrier: %w", cryptography.ErrDecryptionFailed)
		}
		if raw[0] != valueFormatVersion {
			return nil, ErrUnsupportedVersion
		}

		ad := additionalData(raw[0], key)
		plaintext, err := b.cipher.Decrypt(barrierKey, raw[1:], ad)
		if err != nil {
			return nil, fmt.Errorf("barrier: %w", err)
		}
		return plaintext, nil
	})
}

func (b *AEADBarrier) Delete(ctx context.Context, key string) error {
	return b.withKey(func(_ []byte) error {
		if err := b.physical.Delete(ctx, key); err != nil {
			return fmt.Errorf("barrier: %w", err)
		}
		return nil
	})
}

func (b *AEADBarrier) List(ctx context.Context, prefix string) ([]string, error) {
	return withKeyValue(b, func(_ []byte) ([]string, error) {
		keys, err := b.physical.List(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("barrier: %w", err)
		}
		return keys, nil
	})
}

// additionalData binds a ciphertext to its storage key and format version,
// so it cannot be moved or relabelled.
func additionalData(version byte, key string) []byte {
	return append([]byte{version}, []byte(key)...)
}

// withKey maps a missing key to ErrSealed and holds the key for the whole call,
// so a seal waits for it; f wraps its own errors.
func (b *AEADBarrier) withKey(f func(barrierKey []byte) error) error {
	err := b.keys.WithKey(f)
	if errors.Is(err, cryptography.ErrNoActiveKey) {
		return ErrSealed
	}
	return err
}

// withKeyValue is withKey for callbacks that produce a value; T must not alias the key.
func withKeyValue[T any](b *AEADBarrier, f func(barrierKey []byte) (T, error)) (T, error) {
	var v T
	err := b.withKey(func(barrierKey []byte) error {
		var err error
		v, err = f(barrierKey)
		return err
	})
	return v, err
}

package system

import (
	"context"
	"time"
)

// Repository persists the initialization state; Load returns ErrNotInitialized before the first Save.
type Repository interface {
	Save(ctx context.Context, state InitializationState) error
	Load(ctx context.Context) (InitializationState, error)
}

type SecretSharing interface {
	Split(secret []byte, shares, threshold int) ([][]byte, error)
	Combine(shares [][]byte) ([]byte, error)
}

type KeyWrapper interface {
	Wrap(wrappingKey []byte, key []byte, additionalData []byte) ([]byte, error)
	Unwrap(wrappingKey []byte, wrappedKey []byte, additionalData []byte) ([]byte, error)
}

type RandomGenerator interface {
	Bytes(n int) ([]byte, error)
}

type ActiveKeyController interface {
	Install(key []byte) error
	Clear()
	IsInstalled() bool
}

type Clock interface {
	Now() time.Time
}

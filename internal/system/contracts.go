package system

import (
	"context"
	"time"
)

type Repository interface {
	IsInitialized(ctx context.Context) (bool, error)
	SaveInitialization(ctx context.Context, state InitializationState) error
	LoadSealConfiguration(ctx context.Context) (SealConfiguration, error)
	LoadEncryptedKey(ctx context.Context) (EncryptedKey, error)
}

type UnsealedResource interface {
	Activate() error
	Deactivate()
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

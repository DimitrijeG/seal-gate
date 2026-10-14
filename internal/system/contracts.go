package system

import (
	"context"
	"time"
)

// Repository persists the initialization state; Load returns ErrNotInitialized
// before the first Save, and ErrUnreadableRecord for a stored record it cannot read.
type Repository interface {
	Save(ctx context.Context, state InitializationState) error
	Load(ctx context.Context) (InitializationState, error)
}

// SecretSharing splits the root key into shares; Combine below the threshold
// returns wrong bytes, not an error, so the caller must verify the result.
type SecretSharing interface {
	Split(secret []byte, shares, threshold int) ([][]byte, error)
	Combine(shares [][]byte) ([]byte, error)
}

// KeyWrapper encrypts the barrier key under the root key; Unwrap fails unless
// the wrapping key and additionalData match what Wrap was given.
type KeyWrapper interface {
	Wrap(wrappingKey []byte, key []byte, additionalData []byte) ([]byte, error)
	Unwrap(wrappingKey []byte, wrappedKey []byte, additionalData []byte) ([]byte, error)
}

// RandomGenerator returns cryptographically secure random bytes, for keys and tokens.
type RandomGenerator interface {
	Bytes(n int) ([]byte, error)
}

// ActiveKeyController holds the barrier key while unsealed; Install copies
// the key, so the caller may zero its own, and Clear zeroes the held copy.
type ActiveKeyController interface {
	Install(key []byte) error
	Clear()
	IsInstalled() bool
}

// Clock is the service's time source, so tests can fix it.
type Clock interface {
	Now() time.Time
}

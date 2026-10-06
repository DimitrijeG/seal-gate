// Package storage defines the key-value contract every physical backend implements.
package storage

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Get when the key has no value.
var ErrNotFound = errors.New("storage: not found")

// Backend stores opaque values under string keys. It does not keep value after
// Put returns, the slice Get returns belongs to the caller, and one Put is atomic.
type Backend interface {
	Name() string
	// Get returns ErrNotFound when key has no value.
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, value []byte) error
	// Delete of a missing key is not an error.
	Delete(ctx context.Context, key string) error
	// List returns the keys starting with prefix, sorted; an empty prefix matches every key.
	List(ctx context.Context, prefix string) ([]string, error)
	Close() error
}

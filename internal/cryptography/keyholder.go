package cryptography

import (
	"bytes"
	"errors"
	"sync"
)

// ErrNoActiveKey is returned by WithKey while sealed.
var ErrNoActiveKey = errors.New("cryptography: no active key")

// KeyHolder lends the barrier key only for the duration of a callback, so no
// reference to it outlives a seal.
type KeyHolder struct {
	mu  sync.RWMutex
	key []byte
}

func NewKeyHolder() *KeyHolder {
	return &KeyHolder{}
}

// WithKey lends the key for the duration of fn, which must not retain or modify it.
func (kh *KeyHolder) WithKey(fn func(key []byte) error) error {
	kh.mu.RLock()
	defer kh.mu.RUnlock()

	if kh.key == nil {
		return ErrNoActiveKey
	}

	return fn(kh.key)
}

// Install replaces the key, clearing any previous one.
// The caller owns the key and may zero it.
func (kh *KeyHolder) Install(key []byte) error {
	kh.mu.Lock()
	defer kh.mu.Unlock()

	if len(key) != keyLen {
		return ErrInvalidKeyLength
	}

	clear(kh.key)
	kh.key = bytes.Clone(key)
	return nil
}

// Clear zeroes and drops the key; WithKey returns ErrNoActiveKey until the next Install.
func (kh *KeyHolder) Clear() {
	kh.mu.Lock()
	defer kh.mu.Unlock()

	clear(kh.key)
	kh.key = nil
}

func (kh *KeyHolder) IsInstalled() bool {
	kh.mu.RLock()
	defer kh.mu.RUnlock()

	return kh.key != nil
}

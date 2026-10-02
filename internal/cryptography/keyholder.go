package cryptography

import (
	"errors"
	"fmt"
	"sync"
)

// ErrNoActiveKey is returned by WithKey while sealed.
var ErrNoActiveKey = errors.New("cryptography: no active key")

// Checked at install so a bad key fails unseal, not the first write.
const activeKeyLen = 32

// KeyHolder lends the barrier key only for the duration of a callback, so no
// reference to it outlives a seal.
type KeyHolder struct {
	mutex sync.RWMutex
	key   []byte
}

func NewKeyHolder() *KeyHolder {
	return &KeyHolder{}
}

// WithKey holds a read lock so Clear can't zero the key mid-use.
// fn must not retain the slice.
func (kh *KeyHolder) WithKey(fn func(key []byte) error) error {
	kh.mutex.RLock()
	defer kh.mutex.RUnlock()

	if kh.key == nil {
		return ErrNoActiveKey
	}
	return fn(kh.key)
}

// Install keeps its own copy, so the caller may zero theirs.
func (kh *KeyHolder) Install(key []byte) error {
	if len(key) != activeKeyLen {
		return fmt.Errorf("cryptography: active key must be %d bytes, got %d", activeKeyLen, len(key))
	}

	kh.mutex.Lock()
	defer kh.mutex.Unlock()

	clear(kh.key)
	kh.key = make([]byte, len(key))
	copy(kh.key, key)
	return nil
}

func (kh *KeyHolder) Clear() {
	kh.mutex.Lock()
	defer kh.mutex.Unlock()

	clear(kh.key)
	kh.key = nil
}

func (kh *KeyHolder) IsInstalled() bool {
	kh.mutex.RLock()
	defer kh.mutex.RUnlock()

	return kh.key != nil
}

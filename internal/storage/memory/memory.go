// Package memory is an in-process storage backend for tests and development; nothing survives a restart.
package memory

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

// Backend keeps values in a map under one lock and copies them on Put and Get.
type Backend struct {
	mu   sync.RWMutex
	data map[string][]byte
}

var _ storage.Backend = (*Backend)(nil)

func New() *Backend {
	return &Backend{data: make(map[string][]byte)}
}

func (m *Backend) Name() string {
	return "memory"
}

func (m *Backend) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if value, ok := m.data[key]; ok {
		return bytes.Clone(value), nil
	}
	return nil, storage.ErrNotFound
}

func (m *Backend) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[key] = bytes.Clone(value)
	return nil
}

func (m *Backend) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

func (m *Backend) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	slices.Sort(keys)
	return keys, nil
}

func (m *Backend) Close() error {
	return nil
}

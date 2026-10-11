package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

// secretRepository stores secrets through the barrier, so storage sees only ciphertext.
type secretRepository struct {
	encrypted *barrier.AEADBarrier
}

var _ secret.Repository = (*secretRepository)(nil)

const (
	secretRecordVersion = 1
	// Every barrier key starts with its domain's prefix,
	// never sys/, so no path reaches the system records.
	secretPrefix = "secrets/"
)

// secretRecord is the stored layout; it changes only with its version.
type secretRecord struct {
	Version int    `json:"version"`
	Value   []byte `json:"value"`
}

func secretKey(path string) string {
	return secretPrefix + path
}

func (r *secretRepository) Put(ctx context.Context, path string, value []byte) error {
	record := secretRecord{Version: secretRecordVersion, Value: value}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}

	err = r.encrypted.Put(ctx, secretKey(path), encoded)
	if errors.Is(err, barrier.ErrSealed) {
		return secret.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *secretRepository) Get(ctx context.Context, path string) ([]byte, error) {
	encoded, err := r.encrypted.Get(ctx, secretKey(path))
	switch {
	case errors.Is(err, barrier.ErrSealed):
		return nil, secret.ErrSealed
	case errors.Is(err, storage.ErrNotFound):
		return nil, secret.ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("repository: %w", err)
	}

	var record secretRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	return record.Value, nil
}

func (r *secretRepository) Delete(ctx context.Context, path string) error {
	err := r.encrypted.Delete(ctx, secretKey(path))
	if errors.Is(err, barrier.ErrSealed) {
		return secret.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *secretRepository) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := r.encrypted.List(ctx, secretKey(prefix))
	if errors.Is(err, barrier.ErrSealed) {
		return nil, secret.ErrSealed
	}
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}

	paths := make([]string, 0, len(keys))
	for _, key := range keys {
		paths = append(paths, strings.TrimPrefix(key, secretPrefix))
	}
	return paths, nil
}

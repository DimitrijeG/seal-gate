package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
)

// secretRepository stores secrets through the barrier, so storage sees only ciphertext.
type secretRepository struct {
	encrypted *barrier.AEADBarrier
}

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
	if err := r.encrypted.Put(ctx, secretKey(path), encoded); err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *secretRepository) Get(ctx context.Context, path string) ([]byte, error) {
	encoded, err := r.encrypted.Get(ctx, secretKey(path))
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}

	var record secretRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	return record.Value, nil
}

func (r *secretRepository) Delete(ctx context.Context, path string) error {
	if err := r.encrypted.Delete(ctx, secretKey(path)); err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *secretRepository) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := r.encrypted.List(ctx, secretKey(prefix))
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}

	paths := make([]string, 0, len(keys))
	for _, key := range keys {
		paths = append(paths, strings.TrimPrefix(key, secretPrefix))
	}
	return paths, nil
}

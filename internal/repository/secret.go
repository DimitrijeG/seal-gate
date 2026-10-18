package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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

// secretRecord is the stored layout; an incompatible change bumps its version.
type secretRecord struct {
	Version int    `json:"version"`
	Value   []byte `json:"value"`
	// Optional, so records written before them decode unmarked and with no TTL.
	Generated bool          `json:"generated,omitempty"`
	TTL       time.Duration `json:"ttl,omitzero"`
	ExpiresAt time.Time     `json:"expires_at,omitzero"`
}

func secretKey(path string) string {
	return secretPrefix + path
}

func (r *secretRepository) Put(ctx context.Context, path string, entry secret.Entry) error {
	record := secretRecord{
		Version:   secretRecordVersion,
		Value:     entry.Value,
		Generated: entry.Generated,
		TTL:       entry.TTL,
		ExpiresAt: entry.ExpiresAt,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	// The record holds the value in base64.
	defer clear(encoded)

	err = r.encrypted.Put(ctx, secretKey(path), encoded)
	if errors.Is(err, barrier.ErrSealed) {
		return secret.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *secretRepository) Get(ctx context.Context, path string) (secret.Entry, error) {
	encoded, err := r.encrypted.Get(ctx, secretKey(path))
	switch {
	case errors.Is(err, barrier.ErrSealed):
		return secret.Entry{}, secret.ErrSealed
	case errors.Is(err, storage.ErrNotFound):
		return secret.Entry{}, secret.ErrNotFound
	case err != nil:
		return secret.Entry{}, fmt.Errorf("repository: %w", err)
	}
	// Safe for the entry returned: Unmarshal decodes the value into a slice of its own.
	defer clear(encoded)

	var record secretRecord
	// The decode error is replaced, not wrapped, or the client would get a 400 about its own body.
	// A failed decode may still have filled in the value, so it is cleared either way.
	if err := json.Unmarshal(encoded, &record); err != nil || record.Version != secretRecordVersion {
		clear(record.Value)
		return secret.Entry{}, secret.ErrUnreadable
	}
	return secret.Entry{
		Value:     record.Value,
		Generated: record.Generated,
		TTL:       record.TTL,
		ExpiresAt: record.ExpiresAt,
	}, nil
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

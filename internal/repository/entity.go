package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

// entityRepository stores entities through the barrier, one key per entity.
type entityRepository struct {
	encrypted *barrier.AEADBarrier
}

var _ identity.EntityRepository = (*entityRepository)(nil)

const (
	entityRecordVersion = 1
	// Every barrier key starts with its domain's prefix,
	// never sys/, so no path reaches the system records.
	entityPrefix = "entities/"
)

// entityRecord is the stored layout; it changes only with its version. The ID is the key, not a field.
// Alias came without a version bump, so a version 1 record without it reads as no alias.
type entityRecord struct {
	Version  int      `json:"version"`
	Alias    string   `json:"alias,omitempty"`
	Policies []string `json:"policies"`
	Groups   []string `json:"groups"`
}

func entityKey(id string) string {
	return entityPrefix + id
}

func (r *entityRepository) Put(ctx context.Context, entity identity.Entity) error {
	record := entityRecord{
		Version:  entityRecordVersion,
		Alias:    entity.Alias,
		Policies: entity.Policies,
		Groups:   entity.Groups,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}

	err = r.encrypted.Put(ctx, entityKey(entity.ID), encoded)
	if errors.Is(err, barrier.ErrSealed) {
		return identity.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *entityRepository) Get(ctx context.Context, id string) (identity.Entity, error) {
	encoded, err := r.encrypted.Get(ctx, entityKey(id))
	if errors.Is(err, barrier.ErrSealed) {
		return identity.Entity{}, identity.ErrSealed
	}
	if errors.Is(err, storage.ErrNotFound) {
		return identity.Entity{}, identity.ErrEntityNotFound
	}
	if err != nil {
		return identity.Entity{}, fmt.Errorf("repository: %w", err)
	}

	var record entityRecord
	// The decode error is replaced, not wrapped: as a *json.SyntaxError it would
	// reach the client as a 400 about its own request body.
	if err := json.Unmarshal(encoded, &record); err != nil {
		return identity.Entity{}, identity.ErrUnreadableEntity
	}
	if record.Version != entityRecordVersion {
		return identity.Entity{}, identity.ErrUnreadableEntity
	}
	return identity.Entity{ID: id, Alias: record.Alias, Policies: record.Policies, Groups: record.Groups}, nil
}

func (r *entityRepository) Delete(ctx context.Context, id string) error {
	err := r.encrypted.Delete(ctx, entityKey(id))
	if errors.Is(err, barrier.ErrSealed) {
		return identity.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *entityRepository) List(ctx context.Context) ([]string, error) {
	names, err := listNames(ctx, r.encrypted, entityPrefix)
	if errors.Is(err, barrier.ErrSealed) {
		return nil, identity.ErrSealed
	}
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	return names, nil
}

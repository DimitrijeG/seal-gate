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

// groupRepository stores groups through the barrier, one key per group.
type groupRepository struct {
	encrypted *barrier.AEADBarrier
}

var _ identity.GroupRepository = (*groupRepository)(nil)

const (
	groupRecordVersion = 1
	// Every barrier key starts with its domain's prefix,
	// never sys/, so no path reaches the system records.
	groupPrefix = "groups/"
)

// groupRecord is the stored layout; it changes only with its version. The ID is the key, not a field.
type groupRecord struct {
	Version  int      `json:"version"`
	Policies []string `json:"policies"`
}

func groupKey(id string) string {
	return groupPrefix + id
}

func (r *groupRepository) Put(ctx context.Context, group identity.Group) error {
	record := groupRecord{
		Version:  groupRecordVersion,
		Policies: group.Policies,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}

	err = r.encrypted.Put(ctx, groupKey(group.ID), encoded)
	if errors.Is(err, barrier.ErrSealed) {
		return identity.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *groupRepository) Get(ctx context.Context, id string) (identity.Group, error) {
	encoded, err := r.encrypted.Get(ctx, groupKey(id))
	if errors.Is(err, barrier.ErrSealed) {
		return identity.Group{}, identity.ErrSealed
	}
	if errors.Is(err, storage.ErrNotFound) {
		return identity.Group{}, identity.ErrGroupNotFound
	}
	if err != nil {
		return identity.Group{}, fmt.Errorf("repository: %w", err)
	}

	var record groupRecord
	// The decode error is replaced, not wrapped: as a *json.SyntaxError it would
	// reach the client as a 400 about its own request body.
	if err := json.Unmarshal(encoded, &record); err != nil {
		return identity.Group{}, identity.ErrUnreadableGroup
	}
	if record.Version != groupRecordVersion {
		return identity.Group{}, identity.ErrUnreadableGroup
	}
	return identity.Group{ID: id, Policies: record.Policies}, nil
}

func (r *groupRepository) Delete(ctx context.Context, id string) error {
	err := r.encrypted.Delete(ctx, groupKey(id))
	if errors.Is(err, barrier.ErrSealed) {
		return identity.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

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

// userRepository stores users through the barrier, one key per username.
type userRepository struct {
	encrypted *barrier.AEADBarrier
}

var _ identity.UserRepository = (*userRepository)(nil)

const (
	userRecordVersion = 1
	// Every barrier key starts with its domain's prefix,
	// never sys/, so no path reaches the system records.
	userPrefix = "users/"
)

// userRecord is the stored layout; it changes only with its version. The name is the key, not a field.
type userRecord struct {
	Version      int    `json:"version"`
	EntityID     string `json:"entity_id"`
	PasswordHash string `json:"password_hash"`
}

func userKey(name string) string {
	return userPrefix + name
}

func (r *userRepository) Put(ctx context.Context, name string, user identity.StoredUser) error {
	record := userRecord{
		Version:      userRecordVersion,
		EntityID:     user.EntityID,
		PasswordHash: user.PasswordHash,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}

	err = r.encrypted.Put(ctx, userKey(name), encoded)
	if errors.Is(err, barrier.ErrSealed) {
		return identity.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

// Get returns the user stored under name; ErrUserNotFound if there is none, ErrUnreadableUser if its record does not decode.
func (r *userRepository) Get(ctx context.Context, name string) (identity.StoredUser, error) {
	encoded, err := r.encrypted.Get(ctx, userKey(name))
	if errors.Is(err, barrier.ErrSealed) {
		return identity.StoredUser{}, identity.ErrSealed
	}
	if errors.Is(err, storage.ErrNotFound) {
		return identity.StoredUser{}, identity.ErrUserNotFound
	}
	if err != nil {
		return identity.StoredUser{}, fmt.Errorf("repository: %w", err)
	}

	var record userRecord
	// The decode error is replaced, not wrapped: as a *json.SyntaxError it would
	// reach the client as a 400 about its own request body.
	if err := json.Unmarshal(encoded, &record); err != nil {
		return identity.StoredUser{}, identity.ErrUnreadableUser
	}
	if record.Version != userRecordVersion {
		return identity.StoredUser{}, identity.ErrUnreadableUser
	}
	return identity.StoredUser{EntityID: record.EntityID, PasswordHash: record.PasswordHash}, nil
}

func (r *userRepository) Delete(ctx context.Context, name string) error {
	err := r.encrypted.Delete(ctx, userKey(name))
	if errors.Is(err, barrier.ErrSealed) {
		return identity.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *userRepository) List(ctx context.Context) ([]string, error) {
	names, err := listNames(ctx, r.encrypted, userPrefix)
	if errors.Is(err, barrier.ErrSealed) {
		return nil, identity.ErrSealed
	}
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	return names, nil
}

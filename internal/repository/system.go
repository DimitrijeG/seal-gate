package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

// systemRepository works on the backend directly: the wrapped key must load while sealed.
type systemRepository struct {
	backend storage.Backend
}

var _ system.Repository = (*systemRepository)(nil)

const (
	initializationRecordVersion = 2
	// sys/ is reserved for records that bypass the barrier; nothing writes there through it.
	initializationKey = "sys/initialization"
)

// initializationRecord is the stored layout; it changes only with its version.
type initializationRecord struct {
	Version       int       `json:"version"`
	Shares        int       `json:"shares"`
	Threshold     int       `json:"threshold"`
	KeyVersion    int       `json:"key_version"`
	WrappedKey    []byte    `json:"wrapped_key"`
	RootTokenHash []byte    `json:"root_token_hash"`
	InitializedAt time.Time `json:"initialized_at"`
}

func toRecord(state system.InitializationState) initializationRecord {
	return initializationRecord{
		Version:       initializationRecordVersion,
		Shares:        state.Config.Shares,
		Threshold:     state.Config.Threshold,
		KeyVersion:    state.EncryptedKey.Version,
		WrappedKey:    state.EncryptedKey.Ciphertext,
		RootTokenHash: state.RootTokenHash[:],
		InitializedAt: state.InitializedAt.UTC(),
	}
}

func (r initializationRecord) state() system.InitializationState {
	state := system.InitializationState{
		Config: system.SealConfiguration{
			Shares:    r.Shares,
			Threshold: r.Threshold,
		},
		EncryptedKey: system.EncryptedKey{
			Ciphertext: r.WrappedKey,
			Version:    r.KeyVersion,
		},
		InitializedAt: r.InitializedAt,
	}
	copy(state.RootTokenHash[:], r.RootTokenHash)
	return state
}

func (r *systemRepository) Save(ctx context.Context, state system.InitializationState) error {
	record := toRecord(state)
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	if err := r.backend.Put(ctx, initializationKey, encoded); err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *systemRepository) Load(ctx context.Context) (system.InitializationState, error) {
	encoded, err := r.backend.Get(ctx, initializationKey)
	if errors.Is(err, storage.ErrNotFound) {
		return system.InitializationState{}, system.ErrNotInitialized
	}
	if err != nil {
		return system.InitializationState{}, fmt.Errorf("repository: %w", err)
	}

	var record initializationRecord
	// The decode error is replaced, not wrapped: as a *json.SyntaxError it would
	// reach the client as a 400 about its own request body.
	if err := json.Unmarshal(encoded, &record); err != nil {
		return system.InitializationState{}, system.ErrUnreadableRecord
	}
	if record.Version != initializationRecordVersion {
		return system.InitializationState{}, system.ErrUnreadableRecord
	}
	if len(record.RootTokenHash) != sha256.Size {
		return system.InitializationState{}, system.ErrUnreadableRecord
	}
	return record.state(), nil
}

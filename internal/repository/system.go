package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

var _ system.Repository = (*systemRepository)(nil)

// systemRepository works on the backend directly: the wrapped key must load while sealed.
type systemRepository struct {
	backend storage.Backend
}

const (
	initializationRecordVersion = 1
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
	InitializedAt time.Time `json:"initialized_at"`
}

func toRecord(state system.InitializationState) initializationRecord {
	return initializationRecord{
		Version:       initializationRecordVersion,
		Shares:        state.Config.Shares,
		Threshold:     state.Config.Threshold,
		KeyVersion:    state.EncryptedKey.Version,
		WrappedKey:    state.EncryptedKey.Ciphertext,
		InitializedAt: state.InitializedAt.UTC(),
	}
}

func (r initializationRecord) state() system.InitializationState {
	return system.InitializationState{
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
	if err := json.Unmarshal(encoded, &record); err != nil {
		return system.InitializationState{}, fmt.Errorf("repository: %w", err)
	}
	return record.state(), nil
}

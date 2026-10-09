package repository_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/repository"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

type storedFields struct {
	Version       int    `json:"version"`
	InitializedAt string `json:"initialized_at"`
}

// The key is part of the stored format, so the test spells it out.
const initializationKey = "sys/initialization"

func newSystemRepository(t *testing.T) (system.Repository, storage.Backend) {
	t.Helper()
	backend := memory.New()
	return repository.NewSet(backend).System, backend
}

func mustSave(t *testing.T, repo system.Repository, state system.InitializationState) {
	t.Helper()
	err := repo.Save(t.Context(), state)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func mustLoad(t *testing.T, repo system.Repository) system.InitializationState {
	t.Helper()
	state, err := repo.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return state
}

func assertStateEqual(t *testing.T, got, want system.InitializationState) {
	t.Helper()
	if got.Config != want.Config { // SealConfiguration has only ints, so == works
		t.Errorf("Config: got %+v, want %+v", got.Config, want.Config)
	}
	if !bytes.Equal(got.EncryptedKey.Ciphertext, want.EncryptedKey.Ciphertext) {
		t.Errorf("Ciphertext: got %x, want %x", got.EncryptedKey.Ciphertext, want.EncryptedKey.Ciphertext)
	}
	if got.EncryptedKey.Version != want.EncryptedKey.Version {
		t.Errorf("EncryptedKey.Version: got %d, want %d", got.EncryptedKey.Version, want.EncryptedKey.Version)
	}
	if !got.InitializedAt.Equal(want.InitializedAt) {
		t.Errorf("InitializedAt: got %v, want %v", got.InitializedAt, want.InitializedAt)
	}
}

func newSystemState() system.InitializationState {
	return system.InitializationState{
		Config:        system.SealConfiguration{Shares: 5, Threshold: 3},
		EncryptedKey:  system.EncryptedKey{Ciphertext: []byte("wrapped"), Version: 1},
		InitializedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
	}
}

func storedRecord(t *testing.T, backend storage.Backend) storedFields {
	t.Helper()
	data, err := backend.Get(t.Context(), initializationKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	var record storedFields
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return record
}

var errBackend = errors.New("backend failed")

// failingBackend fails Get and Put; any other method panics, since nothing should call it.
type failingBackend struct {
	storage.Backend
}

func (failingBackend) Get(context.Context, string) ([]byte, error) { return nil, errBackend }
func (failingBackend) Put(context.Context, string, []byte) error   { return errBackend }

func TestSystemRepository(t *testing.T) {
	t.Run("a saved initialization record loads back", func(t *testing.T) {
		repo, _ := newSystemRepository(t)
		want := newSystemState()

		mustSave(t, repo, want)
		got := mustLoad(t, repo)

		assertStateEqual(t, got, want)
	})

	t.Run("a record saved by one repository loads from another over the same backend", func(t *testing.T) {
		writer, backend := newSystemRepository(t)
		reader := repository.NewSet(backend).System
		want := newSystemState()

		mustSave(t, writer, want)
		got := mustLoad(t, reader)

		assertStateEqual(t, got, want)
	})

	t.Run("loading before any save is ErrNotInitialized", func(t *testing.T) {
		repo, _ := newSystemRepository(t)

		_, err := repo.Load(t.Context())

		if !errors.Is(err, system.ErrNotInitialized) {
			t.Fatalf("got %v, want %v", err, system.ErrNotInitialized)
		}
	})

	t.Run("the record is one key under the reserved sys/ prefix", func(t *testing.T) {
		repo, backend := newSystemRepository(t)
		state := newSystemState()
		want := []string{initializationKey}

		mustSave(t, repo, state)
		keys, err := backend.List(t.Context(), "")
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		if !slices.Equal(keys, want) {
			t.Errorf("got %v, want %v", keys, want)
		}
	})

	t.Run("the stored record is plain JSON, readable without a root key", func(t *testing.T) {
		repo, backend := newSystemRepository(t)
		state := newSystemState()

		mustSave(t, repo, state)
		got, err := backend.Get(t.Context(), initializationKey)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !json.Valid(got) {
			t.Errorf("got %s, want valid JSON", got)
		}
	})

	t.Run("the stored record carries format version 1", func(t *testing.T) {
		repo, backend := newSystemRepository(t)
		state := newSystemState()
		want := 1

		mustSave(t, repo, state)
		record := storedRecord(t, backend)

		if record.Version != want {
			t.Errorf("got %d, want %d", record.Version, want)
		}
	})

	t.Run("the stored time is in UTC", func(t *testing.T) {
		repo, backend := newSystemRepository(t)
		state := newSystemState()
		state.InitializedAt = time.Date(2026, 10, 7, 12, 0, 0, 0, time.FixedZone("CET", 3600))
		want := "2026-10-07T11:00:00Z" // 12:00 CET

		mustSave(t, repo, state)
		record := storedRecord(t, backend)

		if record.InitializedAt != want {
			t.Errorf("got %s, want %s", record.InitializedAt, want)
		}
	})

	t.Run("a record in the version 1 layout loads", func(t *testing.T) {
		repo, backend := newSystemRepository(t)
		stored := `{
			"version": 1,
			"shares": 5,
			"threshold": 3,
			"key_version": 1,
			"wrapped_key": "d3JhcHBlZA==",
			"initialized_at": "2026-10-07T12:00:00Z"
		}`
		want := system.InitializationState{
			Config:        system.SealConfiguration{Shares: 5, Threshold: 3},
			EncryptedKey:  system.EncryptedKey{Ciphertext: []byte("wrapped"), Version: 1},
			InitializedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		}

		err := backend.Put(t.Context(), initializationKey, []byte(stored))
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		got := mustLoad(t, repo)

		assertStateEqual(t, got, want)
	})

	t.Run("a backend failure reaches the caller", func(t *testing.T) {
		state := newSystemState()
		tests := []struct {
			name string
			fn   func(*testing.T, system.Repository) error
		}{
			{"save", func(t *testing.T, repo system.Repository) error {
				return repo.Save(t.Context(), state)
			}},
			{"load", func(t *testing.T, repo system.Repository) error {
				_, err := repo.Load(t.Context())
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				backend := failingBackend{}
				repo := repository.NewSet(backend).System

				err := tt.fn(t, repo)

				if !errors.Is(err, errBackend) {
					t.Errorf("got %v, want %v", err, errBackend)
				}
			})
		}
	})
}

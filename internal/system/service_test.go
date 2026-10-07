package system_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

type fakeRepository struct {
	state   system.InitializationState
	saved   bool
	loadErr error
	saveErr error
}

func (r *fakeRepository) Save(_ context.Context, state system.InitializationState) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.state = state
	r.saved = true
	return nil
}

func (r *fakeRepository) Load(_ context.Context) (system.InitializationState, error) {
	if r.loadErr != nil {
		return system.InitializationState{}, r.loadErr
	}
	if !r.saved {
		return system.InitializationState{}, system.ErrNotInitialized
	}
	return r.state, nil
}

var initTime = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

func newService(t *testing.T) (*system.Service, *fakeRepository, *cryptography.KeyHolder) {
	t.Helper()
	repo := &fakeRepository{}
	keys := cryptography.NewKeyHolder()
	random := cryptography.CryptoRandom{}
	sharing := cryptography.NewShamir(random)
	cipher, err := cryptography.NewAEADCipher("aes-256-gcm")
	if err != nil {
		t.Fatalf("NewAEADCipher: %v", err)
	}
	wrapper := cryptography.NewKeyWrapper(cipher)

	keyring := system.NewKeyring(repo, sharing, wrapper, random, keys)
	clock := fakeClock{now: initTime}
	return system.NewService(keyring, clock), repo, keys
}

func TestService(t *testing.T) {
	t.Run("init rejects a seal configuration that cannot make valid shares", func(t *testing.T) {
		tests := []struct {
			name      string
			shares    int
			threshold int
		}{
			{"threshold of zero", 5, 0},
			{"threshold of one", 5, 1},
			{"threshold greater than shares", 5, 6},
			{"more than 255 shares", 256, 3},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newService(t)
				cfg := system.SealConfiguration{Shares: tt.shares, Threshold: tt.threshold}

				_, err := s.Init(t.Context(), cfg)

				if !errors.Is(err, system.ErrInvalidSealConfig) {
					t.Errorf("got %v, want %v", err, system.ErrInvalidSealConfig)
				}
			})
		}
	})

	t.Run("init accepts valid configurations", func(t *testing.T) {
		tests := []struct {
			name      string
			shares    int
			threshold int
		}{
			{"threshold of two", 5, 2},
			{"threshold equal to shares", 5, 5},
			{"255 shares", 255, 3},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newService(t)
				cfg := system.SealConfiguration{Shares: tt.shares, Threshold: tt.threshold}

				result, err := s.Init(t.Context(), cfg)
				if err != nil {
					t.Fatalf("Init: %v", err)
				}

				if len(result.Shares) != tt.shares {
					t.Errorf("got %d, want %d", len(result.Shares), tt.shares)
				}
			})
		}
	})

	t.Run("a second init is refused", func(t *testing.T) {
		s, _, _ := newService(t)
		cfg := system.SealConfiguration{Shares: 5, Threshold: 3}

		_, err := s.Init(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		_, err = s.Init(t.Context(), cfg)

		if !errors.Is(err, system.ErrAlreadyInitialized) {
			t.Errorf("got %v, want %v", err, system.ErrAlreadyInitialized)
		}
	})

	t.Run("init does not overwrite when the record cannot be read", func(t *testing.T) {
		s, repo, _ := newService(t)
		cfg := system.SealConfiguration{Shares: 5, Threshold: 3}
		loadErr := errors.New("load failed")
		repo.loadErr = loadErr

		_, err := s.Init(t.Context(), cfg)

		if !errors.Is(err, loadErr) {
			t.Errorf("got %v, want %v", err, loadErr)
		}
		if repo.saved {
			t.Error("Save called after a failed Load")
		}
	})

	t.Run("init returns no shares when the save fails", func(t *testing.T) {
		s, repo, _ := newService(t)
		cfg := system.SealConfiguration{Shares: 5, Threshold: 3}
		saveErr := errors.New("save failed")
		repo.saveErr = saveErr

		result, err := s.Init(t.Context(), cfg)

		if !errors.Is(err, saveErr) {
			t.Errorf("got %v, want %v", err, saveErr)
		}
		if len(result.Shares) != 0 {
			t.Errorf("got %d, want 0", len(result.Shares))
		}
	})

	t.Run("init records the time from the clock", func(t *testing.T) {
		s, repo, _ := newService(t)
		cfg := system.SealConfiguration{Shares: 5, Threshold: 3}

		_, err := s.Init(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}

		if !repo.state.InitializedAt.Equal(initTime) {
			t.Errorf("got %v, want %v", repo.state.InitializedAt, initTime)
		}
	})

	t.Run("init leaves the instance sealed", func(t *testing.T) {
		s, _, _ := newService(t)
		cfg := system.SealConfiguration{Shares: 5, Threshold: 3}
		want := system.Status{Initialized: true, Sealed: true, Config: cfg}

		_, err := s.Init(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("status before init reports uninitialized and sealed with no configuration", func(t *testing.T) {
		s, _, _ := newService(t)
		want := system.Status{Sealed: true}

		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("status returns a repository failure instead of reporting a state", func(t *testing.T) {
		s, repo, _ := newService(t)
		loadErr := errors.New("load failed")
		repo.loadErr = loadErr

		_, err := s.Status(t.Context())
		if !errors.Is(err, loadErr) {
			t.Errorf("got %v, want %v", err, loadErr)
		}
	})
}

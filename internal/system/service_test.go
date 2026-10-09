package system_test

import (
	"bytes"
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

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

var (
	sealConfig = system.SealConfiguration{Shares: 5, Threshold: 3}
	initTime   = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
)

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

func newInitializedService(t *testing.T) (*system.Service, *fakeRepository, *cryptography.KeyHolder, [][]byte) {
	t.Helper()
	s, repo, keys := newService(t)
	result, err := s.Init(t.Context(), sealConfig)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s, repo, keys, result.Shares
}

func newUnsealedService(t *testing.T) (*system.Service, *cryptography.KeyHolder) {
	t.Helper()
	s, _, keys, shares := newInitializedService(t)
	unsealWith(t, s, shares[:sealConfig.Threshold])
	return s, keys
}

// unsealWith submits shares that are all expected to be accepted.
func unsealWith(t *testing.T, s *system.Service, shares [][]byte) {
	t.Helper()
	for _, share := range shares {
		if _, err := s.Unseal(t.Context(), share); err != nil {
			t.Fatalf("Unseal: %v", err)
		}
	}
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
		s, _, _, _ := newInitializedService(t)

		_, err := s.Init(t.Context(), sealConfig)

		if !errors.Is(err, system.ErrAlreadyInitialized) {
			t.Errorf("got %v, want %v", err, system.ErrAlreadyInitialized)
		}
	})

	t.Run("init does not overwrite when the record cannot be read", func(t *testing.T) {
		s, repo, _ := newService(t)
		loadErr := errors.New("load failed")
		repo.loadErr = loadErr

		_, err := s.Init(t.Context(), sealConfig)

		if !errors.Is(err, loadErr) {
			t.Errorf("got %v, want %v", err, loadErr)
		}
		if repo.saved {
			t.Error("Save called after a failed Load")
		}
	})

	t.Run("init returns no shares when the save fails", func(t *testing.T) {
		s, repo, _ := newService(t)
		saveErr := errors.New("save failed")
		repo.saveErr = saveErr

		result, err := s.Init(t.Context(), sealConfig)

		if !errors.Is(err, saveErr) {
			t.Errorf("got %v, want %v", err, saveErr)
		}
		if len(result.Shares) != 0 {
			t.Errorf("got %d, want 0", len(result.Shares))
		}
	})

	t.Run("init records the time from the clock", func(t *testing.T) {
		s, repo, _ := newService(t)

		_, err := s.Init(t.Context(), sealConfig)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}

		if !repo.state.InitializedAt.Equal(initTime) {
			t.Errorf("got %v, want %v", repo.state.InitializedAt, initTime)
		}
	})

	t.Run("init leaves the instance sealed", func(t *testing.T) {
		s, _, _ := newService(t)
		want := system.Status{Initialized: true, Sealed: true, Config: sealConfig}

		_, err := s.Init(t.Context(), sealConfig)
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

	t.Run("unseal below the threshold reports progress and stays sealed", func(t *testing.T) {
		s, _, _, shares := newInitializedService(t)
		want := system.Status{
			Initialized: true,
			Sealed:      true,
			Config:      sealConfig,
			Progress:    1,
		}

		got, err := s.Unseal(t.Context(), shares[0])
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("status reports the unseal progress", func(t *testing.T) {
		s, _, _, shares := newInitializedService(t)
		want := system.Status{
			Initialized: true,
			Sealed:      true,
			Config:      sealConfig,
			Progress:    1,
		}

		_, err := s.Unseal(t.Context(), shares[0])
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("unseal with threshold shares unseals", func(t *testing.T) {
		s, _, keys, shares := newInitializedService(t)
		want := system.Status{
			Initialized: true,
			Sealed:      false,
			Config:      sealConfig,
			Progress:    0,
		}

		var err error
		var got system.Status
		for _, share := range shares[:sealConfig.Threshold] {
			got, err = s.Unseal(t.Context(), share)
			if err != nil {
				t.Fatalf("Unseal: %v", err)
			}
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if !keys.IsInstalled() {
			t.Error("IsInstalled: got false, want true")
		}
	})

	t.Run("status after unseal reports unsealed", func(t *testing.T) {
		s, _ := newUnsealedService(t)
		want := system.Status{
			Initialized: true,
			Sealed:      false,
			Config:      sealConfig,
			Progress:    0,
		}

		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("unseal rejects an empty share without counting it", func(t *testing.T) {
		tests := []struct {
			name  string
			share []byte
		}{
			{"nil share", nil},
			{"empty share", []byte{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _, _ := newInitializedService(t)
				want := system.Status{
					Initialized: true,
					Sealed:      true,
					Config:      sealConfig,
					Progress:    0,
				}

				_, err := s.Unseal(t.Context(), tt.share)
				if !errors.Is(err, system.ErrInvalidShare) {
					t.Errorf("Unseal: got %v, want %v", err, system.ErrInvalidShare)
				}

				got, err := s.Status(t.Context())
				if err != nil {
					t.Fatalf("Status: %v", err)
				}

				if got != want {
					t.Errorf("Status: got %+v, want %+v", got, want)
				}
			})
		}
	})

	t.Run("a bad share at the threshold fails and stays sealed", func(t *testing.T) {
		tests := []struct {
			name    string
			corrupt func(share []byte) []byte
		}{
			// Combine accepts it and returns the wrong root key; Unwrap fails.
			{"changed value", func(share []byte) []byte {
				bad := bytes.Clone(share)
				bad[0] ^= 1
				return bad
			}},
			// Combine rejects it.
			{"wrong length", func(share []byte) []byte {
				return bytes.Clone(share[:len(share)-1])
			}},
		}

		last := sealConfig.Threshold - 1
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, keys, shares := newInitializedService(t)

				unsealWith(t, s, shares[:last])
				_, err := s.Unseal(t.Context(), tt.corrupt(shares[last]))

				if !errors.Is(err, system.ErrInvalidShare) {
					t.Errorf("Unseal: got %v, want %v", err, system.ErrInvalidShare)
				}
				if keys.IsInstalled() {
					t.Error("IsInstalled: got true, want false")
				}
			})
		}
	})

	t.Run("a failed unseal starts over", func(t *testing.T) {
		s, _, keys, shares := newInitializedService(t)
		bad := bytes.Clone(shares[len(shares)-1])
		bad[0] ^= 1
		want := system.Status{
			Initialized: true,
			Sealed:      true,
			Config:      sealConfig,
			Progress:    0,
		}

		unsealWith(t, s, shares[:sealConfig.Threshold-1])
		_, err := s.Unseal(t.Context(), bad)
		if !errors.Is(err, system.ErrInvalidShare) {
			t.Fatalf("Unseal: %v", err)
		}
		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("Status: got %+v, want %+v", got, want)
		}

		unsealWith(t, s, shares[:sealConfig.Threshold])

		if !keys.IsInstalled() {
			t.Error("IsInstalled: got false, want true")
		}
	})

	t.Run("a tampered initialization record does not unseal", func(t *testing.T) {
		tests := []struct {
			name   string
			tamper func(state *system.InitializationState)
			submit int
		}{
			{"raised threshold", func(s *system.InitializationState) { s.Config.Threshold = 4 }, 4},
			{"changed share count", func(s *system.InitializationState) { s.Config.Shares = 6 }, 3},
			{"changed key version", func(s *system.InitializationState) { s.EncryptedKey.Version = 2 }, 3},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo, keys, shares := newInitializedService(t)
				last := tt.submit - 1

				tt.tamper(&repo.state)
				unsealWith(t, s, shares[:last])
				_, err := s.Unseal(t.Context(), shares[last])

				if !errors.Is(err, system.ErrInvalidShare) {
					t.Errorf("Unseal: got %v, want %v", err, system.ErrInvalidShare)
				}
				if keys.IsInstalled() {
					t.Error("IsInstalled: got true, want false")
				}
			})
		}
	})

	t.Run("unseal before init is ErrNotInitialized", func(t *testing.T) {
		s, _, _ := newService(t)

		_, err := s.Unseal(t.Context(), []byte{1, 2, 3})

		if !errors.Is(err, system.ErrNotInitialized) {
			t.Errorf("got %v, want %v", err, system.ErrNotInitialized)
		}
	})

	t.Run("unseal while unsealed is ErrAlreadyUnsealed", func(t *testing.T) {
		s, _ := newUnsealedService(t)

		_, err := s.Unseal(t.Context(), []byte{1, 2, 3})

		if !errors.Is(err, system.ErrAlreadyUnsealed) {
			t.Errorf("got %v, want %v", err, system.ErrAlreadyUnsealed)
		}
	})

	t.Run("seal clears the key", func(t *testing.T) {
		s, keys := newUnsealedService(t)

		s.Seal(t.Context())

		if keys.IsInstalled() {
			t.Error("got true, want false")
		}
	})

	t.Run("seal discards buffered shares", func(t *testing.T) {
		s, _, _, shares := newInitializedService(t)
		want := system.Status{
			Initialized: true,
			Sealed:      true,
			Config:      sealConfig,
			Progress:    0,
		}

		unsealWith(t, s, shares[:sealConfig.Threshold-1])
		s.Seal(t.Context())

		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("Status: got %+v, want %+v", got, want)
		}
	})
}

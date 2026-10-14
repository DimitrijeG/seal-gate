package system_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
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

// racingRepository makes the first Load wait for a second, so an unguarded Init
// really interleaves.
type racingRepository struct {
	fakeRepository
	loads   atomic.Int32
	arrived chan struct{}
}

func newRacingRepository() *racingRepository {
	return &racingRepository{arrived: make(chan struct{})}
}

func (r *racingRepository) Load(ctx context.Context) (system.InitializationState, error) {
	switch r.loads.Add(1) {
	case 1:
		select {
		case <-r.arrived:
		case <-time.After(100 * time.Millisecond):
		}
	case 2:
		close(r.arrived)
	}
	return r.fakeRepository.Load(ctx)
}

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

var (
	sealConfig = system.SealConfiguration{Shares: 5, Threshold: 3}
	initTime   = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	principal  = authorization.NewEntityPrincipal("0123456789abcdef0123456789abcdef", "ops")
)

func newService(t *testing.T) (*system.Service, *fakeRepository, *cryptography.KeyHolder) {
	t.Helper()
	repo := &fakeRepository{}
	s, keys := newServiceWith(t, repo, &fakeAuthorizer{})
	return s, repo, keys
}

func newServiceWith(t *testing.T, repo system.Repository, authorizer authorization.Authorizer) (*system.Service, *cryptography.KeyHolder) {
	t.Helper()
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
	return system.NewService(keyring, clock, authorizer), keys
}

func initialize(t *testing.T, s *system.Service) system.InitResult {
	t.Helper()
	result, err := s.Init(t.Context(), sealConfig)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return result
}

func newInitializedService(t *testing.T) (*system.Service, *fakeRepository, *cryptography.KeyHolder, [][]byte) {
	t.Helper()
	s, repo, keys := newService(t)
	result := initialize(t, s)
	return s, repo, keys, result.Shares
}

func newUnsealedService(t *testing.T) (*system.Service, *cryptography.KeyHolder) {
	t.Helper()
	return newUnsealedServiceWith(t, &fakeAuthorizer{})
}

func newUnsealedServiceWith(t *testing.T, authorizer authorization.Authorizer) (*system.Service, *cryptography.KeyHolder) {
	t.Helper()
	s, keys := newServiceWith(t, &fakeRepository{}, authorizer)
	unsealWith(t, s, initialize(t, s).Shares[:sealConfig.Threshold])
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

	t.Run("two concurrent inits: one succeeds, the other is refused", func(t *testing.T) {
		repo := newRacingRepository()
		s, _ := newServiceWith(t, repo, &fakeAuthorizer{})

		var errs [2]error
		var wg sync.WaitGroup
		for i := range errs {
			wg.Go(func() { _, errs[i] = s.Init(t.Context(), sealConfig) })
		}
		wg.Wait()

		var succeeded, refused int
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, system.ErrAlreadyInitialized):
				refused++
			default:
				t.Errorf("Init: got %v, want nil or %v", err, system.ErrAlreadyInitialized)
			}
		}

		if succeeded != 1 {
			t.Errorf("got %d successes, want 1", succeeded)
		}
		if refused != 1 {
			t.Errorf("got %d refused, want 1", refused)
		}
	})

	t.Run("concurrent init, unseal, reset, seal, status and root checks do not race", func(t *testing.T) {
		s, _, _ := newService(t)
		ctx, junk := t.Context(), []byte{1, 2, 3}

		// Errors depend on ordering, so they are ignored; -race is what judges this.
		var wg sync.WaitGroup
		for range 5 {
			wg.Go(func() { _, _ = s.Init(ctx, sealConfig) })
			wg.Go(func() { _, _ = s.Unseal(ctx, junk) })
			wg.Go(func() { _, _ = s.ResetUnseal(ctx) })
			wg.Go(func() { _ = s.Seal(ctx, principal) })
			wg.Go(func() { _, _ = s.Status(ctx) })
			wg.Go(func() { s.IsRoot(junk) })
		}
		wg.Wait()

		if _, err := s.Status(ctx); err != nil {
			t.Fatalf("Status: %v", err)
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

	t.Run("init returns a root token of 32 bytes", func(t *testing.T) {
		s, _, _ := newService(t)

		result, err := s.Init(t.Context(), sealConfig)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}

		if len(result.RootToken) != 32 {
			t.Errorf("got %d, want 32", len(result.RootToken))
		}
	})

	t.Run("two inits return different root tokens", func(t *testing.T) {
		first, _, _ := newService(t)
		second, _, _ := newService(t)

		a, err := first.Init(t.Context(), sealConfig)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		b, err := second.Init(t.Context(), sealConfig)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}

		if bytes.Equal(a.RootToken, b.RootToken) {
			t.Errorf("got equal tokens %x, want different", a.RootToken)
		}
	})

	t.Run("init stores the hash of the root token", func(t *testing.T) {
		s, repo, _ := newService(t)

		result, err := s.Init(t.Context(), sealConfig)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}

		want := sha256.Sum256(result.RootToken)
		if repo.state.RootTokenHash != want {
			t.Errorf("got %x, want %x", repo.state.RootTokenHash, want)
		}
	})

	t.Run("init wraps the key under format version 2", func(t *testing.T) {
		s, repo, _ := newService(t)

		_, err := s.Init(t.Context(), sealConfig)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}

		if repo.state.EncryptedKey.Version != 2 {
			t.Errorf("got %d, want 2", repo.state.EncryptedKey.Version)
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
			{"changed key version", func(s *system.InitializationState) { s.EncryptedKey.Version = 3 }, 3},
			{"changed root token hash", func(s *system.InitializationState) { s.RootTokenHash[0] ^= 1 }, 3},
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

		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

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
		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("Status: got %+v, want %+v", got, want)
		}
	})

	t.Run("a reset after a share reports no progress", func(t *testing.T) {
		s, _, _, shares := newInitializedService(t)
		want := system.Status{
			Initialized: true,
			Sealed:      true,
			Config:      sealConfig,
			Progress:    0,
		}

		unsealWith(t, s, shares[:1])
		got, err := s.ResetUnseal(t.Context())
		if err != nil {
			t.Fatalf("ResetUnseal: %v", err)
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("status after a reset reports no progress", func(t *testing.T) {
		s, _, _, shares := newInitializedService(t)
		want := system.Status{
			Initialized: true,
			Sealed:      true,
			Config:      sealConfig,
			Progress:    0,
		}

		unsealWith(t, s, shares[:1])
		if _, err := s.ResetUnseal(t.Context()); err != nil {
			t.Fatalf("ResetUnseal: %v", err)
		}
		got, err := s.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a reset while unsealed is ErrAlreadyUnsealed", func(t *testing.T) {
		s, _ := newUnsealedService(t)

		_, err := s.ResetUnseal(t.Context())

		if !errors.Is(err, system.ErrAlreadyUnsealed) {
			t.Errorf("got %v, want %v", err, system.ErrAlreadyUnsealed)
		}
	})

	t.Run("a reset before init is ErrNotInitialized", func(t *testing.T) {
		s, _, _ := newService(t)

		_, err := s.ResetUnseal(t.Context())

		if !errors.Is(err, system.ErrNotInitialized) {
			t.Errorf("got %v, want %v", err, system.ErrNotInitialized)
		}
	})

	t.Run("after unseal, the init root token is root", func(t *testing.T) {
		s, _, _ := newService(t)
		result := initialize(t, s)
		unsealWith(t, s, result.Shares[:sealConfig.Threshold])

		if !s.IsRoot(result.RootToken) {
			t.Error("got false, want true")
		}
	})

	t.Run("after unseal, a token that is not the root token is not root", func(t *testing.T) {
		tests := []struct {
			name  string
			token func(root []byte) []byte
		}{
			{"same length, other bytes", func(root []byte) []byte {
				other := bytes.Clone(root)
				other[0] ^= 1
				return other
			}},
			{"nil token", func([]byte) []byte { return nil }},
			{"empty token", func([]byte) []byte { return []byte{} }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newService(t)
				result := initialize(t, s)
				unsealWith(t, s, result.Shares[:sealConfig.Threshold])

				if s.IsRoot(tt.token(result.RootToken)) {
					t.Error("got true, want false")
				}
			})
		}
	})

	t.Run("initialized but sealed, the root token is not root", func(t *testing.T) {
		s, _, _ := newService(t)
		result := initialize(t, s)

		if s.IsRoot(result.RootToken) {
			t.Error("got true, want false")
		}
	})

	t.Run("after seal, the root token is not root", func(t *testing.T) {
		s, _, _ := newService(t)
		result := initialize(t, s)
		unsealWith(t, s, result.Shares[:sealConfig.Threshold])

		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

		if s.IsRoot(result.RootToken) {
			t.Error("got true, want false")
		}
	})

	t.Run("a tampered record's root token hash is never trusted", func(t *testing.T) {
		s, repo, _ := newService(t)
		result := initialize(t, s)
		attacker := []byte("a token the attacker chose")
		last := sealConfig.Threshold - 1

		repo.state.RootTokenHash = sha256.Sum256(attacker)
		unsealWith(t, s, result.Shares[:last])
		if _, err := s.Unseal(t.Context(), result.Shares[last]); !errors.Is(err, system.ErrInvalidShare) {
			t.Fatalf("Unseal: %v", err)
		}

		if s.IsRoot(attacker) {
			t.Error("got true, want false")
		}
	})
}

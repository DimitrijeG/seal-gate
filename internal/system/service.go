// Package system owns the seal lifecycle: initialization, unsealing, sealing, and the lifetime of the active key.
package system

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// Service runs the seal lifecycle: it decides when keys move, and Keyring moves them.
type Service struct {
	mu         sync.Mutex
	keyring    *Keyring
	clock      Clock
	authorizer authorization.Authorizer
}

func NewService(keyring *Keyring, clock Clock, authorizer authorization.Authorizer) *Service {
	return &Service{
		keyring:    keyring,
		clock:      clock,
		authorizer: authorizer,
	}
}

// InitResult carries the unseal shares and the root token, the only copies that will ever exist.
type InitResult struct {
	Shares    [][]byte
	RootToken []byte
}

// Status reports where the instance is in the seal lifecycle; Config is zero before init.
type Status struct {
	Initialized bool
	Sealed      bool
	Config      SealConfiguration
	Progress    int
}

// maxShares is Split's limit, checked here so a client gets ErrInvalidSealConfig, not a 500.
const maxShares = 255

// Init validates cfg, records the initialization and returns the shares and root token;
// a second call fails with ErrAlreadyInitialized.
func (s *Service) Init(ctx context.Context, cfg SealConfiguration) (InitResult, error) {
	if cfg.Threshold <= 1 || cfg.Threshold > cfg.Shares || cfg.Shares > maxShares {
		return InitResult{}, ErrInvalidSealConfig
	}

	// Held across check and save so two inits cannot both pass the check.
	// Process-local: it assumes one instance per backend.
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.keyring.load(ctx)
	if err == nil {
		return InitResult{}, ErrAlreadyInitialized
	}
	if !errors.Is(err, ErrNotInitialized) {
		return InitResult{}, err
	}

	return s.keyring.initialize(ctx, cfg, s.clock.Now())
}

func (s *Service) status(state InitializationState) Status {
	return Status{
		Initialized: true,
		Sealed:      !s.keyring.unlocked(),
		Config:      state.Config,
		Progress:    s.keyring.progress(),
	}
}

// Status reports an uninitialized instance as a status, not an error;
// only a storage failure errors.
func (s *Service) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.keyring.load(ctx)
	if errors.Is(err, ErrNotInitialized) {
		return Status{Sealed: true}, nil
	}
	if err != nil {
		return Status{}, err
	}
	return s.status(state), nil
}

// Unseal buffers one share and unseals at the threshold; a failed attempt
// discards the buffer and returns ErrInvalidShare.
func (s *Service) Unseal(ctx context.Context, share []byte) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.keyring.load(ctx)
	if err != nil {
		return Status{}, err
	}
	if s.keyring.unlocked() {
		return Status{}, ErrAlreadyUnsealed
	}
	if len(share) == 0 {
		return Status{}, ErrInvalidShare
	}

	s.keyring.submit(share)

	if s.keyring.progress() >= state.Config.Threshold {
		if err := s.keyring.unlock(state); err != nil {
			return Status{}, err
		}
	}
	return s.status(state), nil
}

// ResetUnseal discards the buffered shares so an unseal can start over;
// once unsealed it is ErrAlreadyUnsealed, as a share would be.
func (s *Service) ResetUnseal(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.keyring.load(ctx)
	if err != nil {
		return Status{}, err
	}
	if s.keyring.unlocked() {
		return Status{}, ErrAlreadyUnsealed
	}

	s.keyring.discard()
	return s.status(state), nil
}

const sealResource = "system/seal"

// Seal discards buffered shares and clears the key and the root token hash, once principal
// may update system/seal; sealing a sealed instance changes nothing.
func (s *Service) Seal(ctx context.Context, principal authorization.Principal) error {
	// Before the lock: IsRoot takes it on every request, and this may read policies.
	if err := s.authorizer.Authorize(ctx, principal, sealResource, authorization.CapabilityUpdate); err != nil {
		return fmt.Errorf("system: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.keyring.lock()
	return nil
}

// IsRoot reports whether token is the root token verified at the last unseal;
// it is false for every token while sealed.
func (s *Service) IsRoot(token []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.keyring.isRoot(token)
}

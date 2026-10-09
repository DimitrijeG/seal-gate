// Package system owns the seal lifecycle: initialization, unsealing, sealing, and the lifetime of the active key.
package system

import (
	"context"
	"errors"
	"sync"
)

// Service runs the seal lifecycle: it decides when keys move, and Keyring moves them.
type Service struct {
	mu      sync.Mutex
	keyring *Keyring
	clock   Clock
}

func NewService(keyring *Keyring, clock Clock) *Service {
	return &Service{
		keyring: keyring,
		clock:   clock,
	}
}

// InitResult carries the unseal shares, the only copy that will ever exist.
type InitResult struct {
	Shares [][]byte
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

// Init validates cfg, records the initialization and returns the shares;
// a second call fails with ErrAlreadyInitialized.
func (s *Service) Init(ctx context.Context, cfg SealConfiguration) (InitResult, error) {
	if cfg.Threshold <= 1 || cfg.Threshold > cfg.Shares || cfg.Shares > maxShares {
		return InitResult{}, ErrInvalidSealConfig
	}

	// TODO(#17): two concurrent inits can both pass this check and both save.
	_, err := s.keyring.load(ctx)
	if err == nil {
		return InitResult{}, ErrAlreadyInitialized
	}
	if !errors.Is(err, ErrNotInitialized) {
		return InitResult{}, err
	}

	shares, err := s.keyring.initialize(ctx, cfg, s.clock.Now())
	if err != nil {
		return InitResult{}, err
	}

	return InitResult{Shares: shares}, nil
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

// Seal discards buffered shares and clears the key;
// sealing a sealed instance changes nothing.
func (s *Service) Seal(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keyring.lock()
}

// Package system owns the seal lifecycle: initialization, unsealing, sealing, and the lifetime of the active key.
package system

import (
	"context"
	"errors"
)

// Service runs the seal lifecycle: it decides when keys move, and Keyring moves them.
type Service struct {
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
}

// maxShares is Split's limit, checked here so a client gets ErrInvalidSealConfig, not a 500.
const maxShares = 255

// Init validates cfg, records the initialization and returns the shares;
// a second call fails with ErrAlreadyInitialized.
func (s *Service) Init(ctx context.Context, cfg SealConfiguration) (InitResult, error) {
	if cfg.Threshold <= 1 || cfg.Threshold > cfg.Shares || cfg.Shares > maxShares {
		return InitResult{}, ErrInvalidSealConfig
	}

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

// Status reports an uninitialized instance as a status, not an error;
// only a storage failure errors.
func (s *Service) Status(ctx context.Context) (Status, error) {
	state, err := s.keyring.load(ctx)
	if errors.Is(err, ErrNotInitialized) {
		return Status{Sealed: true}, nil
	}
	if err != nil {
		return Status{}, err
	}

	// TODO(#4): ask the key holder once unseal exists.
	return Status{
		Initialized: true,
		Sealed:      true,
		Config:      state.Config,
	}, nil
}

package system

import (
	"context"
)

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

type InitResult struct {
	Shares [][]byte
}

func (s *Service) Init(ctx context.Context, cfg SealConfiguration) (InitResult, error) {
	if cfg.Threshold < 2 || cfg.Threshold > cfg.Shares {
		return InitResult{}, ErrInvalidSealConfig
	}

	// A second init would overwrite the wrapped key and orphan every share.
	initialized, err := s.keyring.isInitialized(ctx)
	if err != nil {
		return InitResult{}, err
	}
	if initialized {
		return InitResult{}, ErrAlreadyInitialized
	}

	shares, err := s.keyring.generate(ctx, cfg, s.clock.Now())
	return InitResult{Shares: shares}, err
}

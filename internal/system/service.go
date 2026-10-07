// Package system owns the seal lifecycle: initialization, unsealing, sealing, and the lifetime of the active key.
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
	// TODO(#4): validate the seal configuration, refuse a second init, and return the shares.
	return InitResult{}, errNotImplemented
}

package system

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Keyring owns key material, leaving Service with only the state machine.
// Methods are unexported so only the state machine decides when keys move.
type Keyring struct {
	repo    Repository
	sharing SecretSharing
	wrapper KeyWrapper
	random  RandomGenerator
	active  ActiveKeyController
}

func NewKeyring(
	repo Repository,
	sharing SecretSharing,
	wrapper KeyWrapper,
	random RandomGenerator,
	active ActiveKeyController,
) *Keyring {
	return &Keyring{repo: repo, sharing: sharing, wrapper: wrapper, random: random, active: active}
}

func (k *Keyring) initialize(ctx context.Context, cfg SealConfiguration, now time.Time) ([][]byte, error) {
	state := InitializationState{
		Config:        cfg,
		InitializedAt: now,
	}

	err := k.repo.Save(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("system: %w", err)
	}
	// TODO(#4): generate, split and wrap a real key.
	return make([][]byte, cfg.Shares), nil
}

// load returns ErrNotInitialized bare, since callers branch on it; other errors are wrapped.
func (k *Keyring) load(ctx context.Context) (InitializationState, error) {
	state, err := k.repo.Load(ctx)
	if err != nil && !errors.Is(err, ErrNotInitialized) {
		return InitializationState{}, fmt.Errorf("system: %w", err)
	}
	return state, err
}

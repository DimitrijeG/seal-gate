package system

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Keyring owns key material, leaving Service with only the state machine.
// Methods are unexported and unsynchronized: only Service calls them, under its lock.
type Keyring struct {
	repo    Repository
	sharing SecretSharing
	wrapper KeyWrapper
	random  RandomGenerator
	active  ActiveKeyController
	buffer  shareBuffer
}

func NewKeyring(
	repo Repository,
	sharing SecretSharing,
	wrapper KeyWrapper,
	random RandomGenerator,
	active ActiveKeyController,
) *Keyring {
	return &Keyring{
		repo:    repo,
		sharing: sharing,
		wrapper: wrapper,
		random:  random,
		active:  active,
	}
}

const (
	keyLen            = 32
	wrapFormatVersion = 1
)

// wrapAdditionalData binds the wrapped key to its format version and seal configuration;
// changing the layout needs a new version.
func wrapAdditionalData(version int, cfg SealConfiguration) []byte {
	return fmt.Appendf(nil, "seal-gate/barrier-key/v%d/%d-of-%d", version, cfg.Threshold, cfg.Shares)
}

func (k *Keyring) initialize(ctx context.Context, cfg SealConfiguration, now time.Time) ([][]byte, error) {
	rootKey, err := k.random.Bytes(keyLen)
	if err != nil {
		return nil, fmt.Errorf("system: %w", err)
	}
	defer clear(rootKey)

	barrierKey, err := k.random.Bytes(keyLen)
	if err != nil {
		return nil, fmt.Errorf("system: %w", err)
	}
	defer clear(barrierKey)

	ad := wrapAdditionalData(wrapFormatVersion, cfg)
	wrapped, err := k.wrapper.Wrap(rootKey, barrierKey, ad)
	if err != nil {
		return nil, fmt.Errorf("system: %w", err)
	}

	shares, err := k.sharing.Split(rootKey, cfg.Shares, cfg.Threshold)
	if err != nil {
		return nil, fmt.Errorf("system: %w", err)
	}

	state := InitializationState{
		Config:        cfg,
		EncryptedKey:  EncryptedKey{Ciphertext: wrapped, Version: wrapFormatVersion},
		InitializedAt: now,
	}

	if err := k.repo.Save(ctx, state); err != nil {
		clearShares(shares)
		return nil, fmt.Errorf("system: %w", err)
	}

	return shares, nil
}

// load returns ErrNotInitialized bare, since callers branch on it; other errors are wrapped.
func (k *Keyring) load(ctx context.Context) (InitializationState, error) {
	state, err := k.repo.Load(ctx)
	if err != nil && !errors.Is(err, ErrNotInitialized) {
		return InitializationState{}, fmt.Errorf("system: %w", err)
	}
	return state, err
}

func (k *Keyring) submit(share []byte) {
	k.buffer.add(share)
}

func (k *Keyring) progress() int {
	return k.buffer.len()
}

func (k *Keyring) unlocked() bool {
	return k.active.IsInstalled()
}

func (k *Keyring) unlock(state InitializationState) error {
	defer k.buffer.clear()

	rootKey, err := k.sharing.Combine(k.buffer.all())
	if err != nil {
		return ErrInvalidShare // generic on purpose: the cause stays hidden
	}
	defer clear(rootKey)

	ad := wrapAdditionalData(state.EncryptedKey.Version, state.Config)
	barrierKey, err := k.wrapper.Unwrap(rootKey, state.EncryptedKey.Ciphertext, ad)
	if err != nil {
		return ErrInvalidShare
	}
	defer clear(barrierKey)

	if err := k.active.Install(barrierKey); err != nil {
		return fmt.Errorf("system: %w", err)
	}
	return nil
}

func (k *Keyring) lock() {
	k.buffer.clear()
	k.active.Clear()
}

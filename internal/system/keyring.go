package system

import (
	"context"
	"time"
)

const keyLen = 32

// Keyring owns key material, leaving Service with only the state machine.
// Methods are unexported so only the state machine decides when keys move.
type Keyring struct {
	repository Repository
	sharing    SecretSharing
	wrapper    KeyWrapper
	random     RandomGenerator
	active     ActiveKeyController
}

func NewKeyring(
	repo Repository,
	sharing SecretSharing,
	wrapper KeyWrapper,
	random RandomGenerator,
	active ActiveKeyController,
) *Keyring {
	return &Keyring{repository: repo, sharing: sharing, wrapper: wrapper, random: random, active: active}
}

// generate does not install the barrier key: requiring an unseal right after
// init proves the operator actually kept the shares.
func (k *Keyring) generate(ctx context.Context, cfg SealConfiguration, now time.Time) ([][]byte, error) {
	barrierKey, err := k.random.Bytes(keyLen)
	if err != nil {
		return nil, err
	}
	defer clear(barrierKey)

	rootKey, err := k.random.Bytes(keyLen)
	if err != nil {
		return nil, err
	}
	defer clear(rootKey)

	shares, err := k.sharing.Split(rootKey, cfg.Shares, cfg.Threshold)
	if err != nil {
		return nil, err
	}

	wrapped, err := k.wrapper.Wrap(rootKey, barrierKey, wrapAdditionalData(wrapFormatVersion))
	if err != nil {
		zeroAll(shares)
		return nil, err
	}

	if err := k.repository.SaveInitialization(ctx, InitializationState{
		Config:        cfg,
		EncryptedKey:  EncryptedKey{Ciphertext: wrapped, Version: wrapFormatVersion},
		InitializedAt: now,
	}); err != nil {
		zeroAll(shares)
		return nil, err
	}

	return shares, nil
}

// unlock relies on the unwrap to catch wrong shares: Combine always yields
// some key, but the AEAD tag only verifies under the right one.
//
//lint:ignore U1000 called by Service once unseal lands (#4)
func (k *Keyring) unlock(ctx context.Context, shares [][]byte) error {
	rootKey, err := k.sharing.Combine(shares)
	if err != nil {
		return err
	}
	defer clear(rootKey)

	wrapped, err := k.repository.LoadEncryptedKey(ctx)
	if err != nil {
		return err
	}
	if wrapped.Version != wrapFormatVersion {
		return ErrUnsupportedKeyFormat
	}

	barrierKey, err := k.wrapper.Unwrap(rootKey, wrapped.Ciphertext, wrapAdditionalData(wrapped.Version))
	if err != nil {
		return ErrInvalidShare
	}
	defer clear(barrierKey)

	return k.active.Install(barrierKey)
}

//lint:ignore U1000 called by Service once seal lands (#4)
func (k *Keyring) lock() {
	k.active.Clear()
}

//lint:ignore U1000 called by Service once status lands (#4)
func (k *Keyring) isUnlocked() bool {
	return k.active.IsInstalled()
}

func (k *Keyring) isInitialized(ctx context.Context) (bool, error) {
	return k.repository.IsInitialized(ctx)
}

//lint:ignore U1000 called by Service once status lands (#4)
func (k *Keyring) configuration(ctx context.Context) (SealConfiguration, error) {
	return k.repository.LoadSealConfiguration(ctx)
}

func zeroAll(slices [][]byte) {
	for _, b := range slices {
		clear(b)
	}
}

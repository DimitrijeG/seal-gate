package system

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// Keyring owns key material for Service. Unsynchronized: Service holds its lock
// across every call into it.
type Keyring struct {
	repo          Repository
	sharing       SecretSharing
	wrapper       KeyWrapper
	random        RandomGenerator
	active        ActiveKeyController
	buffer        shareBuffer
	rootTokenHash []byte // nil while sealed
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
	rootTokenLen      = 32
	wrapFormatVersion = 2
)

// wrapAdditionalData binds the wrapped key to its format version, seal configuration
// and root token hash; changing the layout needs a new version.
func wrapAdditionalData(version int, cfg SealConfiguration, rootTokenHash [sha256.Size]byte) []byte {
	return fmt.Appendf(nil, "seal-gate/barrier-key/v%d/%d-of-%d/%x", version, cfg.Threshold, cfg.Shares, rootTokenHash)
}

func (k *Keyring) initialize(ctx context.Context, cfg SealConfiguration, now time.Time) (_ InitResult, err error) {
	rootKey, err := k.random.Bytes(keyLen)
	if err != nil {
		return InitResult{}, fmt.Errorf("system: %w", err)
	}
	defer clear(rootKey)

	barrierKey, err := k.random.Bytes(keyLen)
	if err != nil {
		return InitResult{}, fmt.Errorf("system: %w", err)
	}
	defer clear(barrierKey)

	rootToken, err := k.random.Bytes(rootTokenLen)
	if err != nil {
		return InitResult{}, fmt.Errorf("system: %w", err)
	}
	// Handed out on success, so cleared only on failure; reads the named err.
	defer func() {
		if err != nil {
			clear(rootToken)
		}
	}()
	rootTokenHash := sha256.Sum256(rootToken)

	ad := wrapAdditionalData(wrapFormatVersion, cfg, rootTokenHash)
	wrapped, err := k.wrapper.Wrap(rootKey, barrierKey, ad)
	if err != nil {
		return InitResult{}, fmt.Errorf("system: %w", err)
	}

	shares, err := k.sharing.Split(rootKey, cfg.Shares, cfg.Threshold)
	if err != nil {
		return InitResult{}, fmt.Errorf("system: %w", err)
	}
	defer func() {
		if err != nil {
			clearShares(shares)
		}
	}()

	state := InitializationState{
		Config:        cfg,
		EncryptedKey:  EncryptedKey{Ciphertext: wrapped, Version: wrapFormatVersion},
		RootTokenHash: rootTokenHash,
		InitializedAt: now,
	}

	if err := k.repo.Save(ctx, state); err != nil {
		return InitResult{}, fmt.Errorf("system: %w", err)
	}

	return InitResult{Shares: shares, RootToken: rootToken}, nil
}

// load returns this package's own sentinels bare: a prefix here would double,
// and Init branches on ErrNotInitialized.
func (k *Keyring) load(ctx context.Context) (InitializationState, error) {
	state, err := k.repo.Load(ctx)
	switch {
	case err == nil:
		return state, nil
	case errors.Is(err, ErrNotInitialized), errors.Is(err, ErrUnreadableRecord):
		return InitializationState{}, err
	default:
		return InitializationState{}, fmt.Errorf("system: %w", err)
	}
}

func (k *Keyring) submit(share []byte) {
	k.buffer.add(share)
}

func (k *Keyring) holds(share []byte) bool {
	return k.buffer.contains(share)
}

func (k *Keyring) discard() {
	k.buffer.clear()
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

	ad := wrapAdditionalData(state.EncryptedKey.Version, state.Config, state.RootTokenHash)
	barrierKey, err := k.wrapper.Unwrap(rootKey, state.EncryptedKey.Ciphertext, ad)
	if err != nil {
		return ErrInvalidShare
	}
	defer clear(barrierKey)

	if err := k.active.Install(barrierKey); err != nil {
		return fmt.Errorf("system: %w", err)
	}

	// Set only now: Unwrap has verified this hash, and the key it guards is in place.
	k.rootTokenHash = state.RootTokenHash[:]
	return nil
}

func (k *Keyring) isRoot(token []byte) bool {
	hash := sha256.Sum256(token)
	return subtle.ConstantTimeCompare(hash[:], k.rootTokenHash) == 1
}

func (k *Keyring) lock() {
	k.buffer.clear()
	k.active.Clear()
	k.rootTokenHash = nil
}

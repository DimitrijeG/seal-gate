// Package system owns the seal lifecycle: initialization, unsealing, sealing, and the lifetime of the active key.
package system

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// Service runs the seal lifecycle: it decides when keys move, and Keyring moves them.
type Service struct {
	// Serializes the keyring, so two inits cannot both pass the initialized check and racing unseals submit shares in turn.
	// Process-local: it assumes one instance per backend.
	mu         sync.Mutex
	keyring    *Keyring
	clock      Clock
	timer      Timer
	authorizer authorization.Authorizer
	resource   UnsealedResource
	generation uint64 // of the last timer armed; an older one's callback clears nothing
	stopExpiry func() bool
	// Outside mu, so authenticating never waits on an unseal or seal; nil from a seal's start until an activation ends.
	rootTokenHash atomic.Pointer[[sha256.Size]byte]
}

// NewService returns a Service that activates resource after each unseal and deactivates it before each seal.
func NewService(keyring *Keyring, clock Clock, timer Timer, authorizer authorization.Authorizer, resource UnsealedResource) *Service {
	return &Service{
		keyring:    keyring,
		clock:      clock,
		timer:      timer,
		authorizer: authorizer,
		resource:   resource,
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

// unsealTimeout is how long buffered shares outlive the last accepted one, so none stay resident when nobody is unsealing.
const unsealTimeout = 10 * time.Minute

// Init validates cfg, records the initialization and returns the shares and root token;
// a second call fails with ErrAlreadyInitialized.
func (s *Service) Init(ctx context.Context, cfg SealConfiguration) (InitResult, error) {
	if cfg.Threshold <= 1 || cfg.Threshold > cfg.Shares || cfg.Shares > maxShares {
		return InitResult{}, ErrInvalidSealConfig
	}

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

// Unseal buffers one share, discarded unsealTimeout after the last accepted one, and unseals at the threshold, then
// activates the resource; a share already buffered is ErrDuplicateShare and changes nothing, a bad share discards the
// buffer and returns ErrInvalidShare, and a failed activation seals again and returns its error.
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
	// Before submit: a refused share never reaches the buffer, so the operators keep their progress.
	if s.keyring.holds(share) {
		return Status{}, ErrDuplicateShare
	}

	s.keyring.submit(share)

	if s.keyring.progress() < state.Config.Threshold {
		s.arm()
		return s.status(state), nil
	}

	s.disarm()
	if err := s.keyring.unlock(state); err != nil {
		return Status{}, err
	}
	// After unlock: what activates reads through the barrier. On failure, lock, so nothing half-unsealed serves.
	if err := s.resource.Activate(ctx); err != nil {
		s.keyring.lock()
		return Status{}, fmt.Errorf("system: %w", err)
	}
	// After Activate: no root request is admitted while it runs, or on one that fails. Unwrap has verified this hash.
	s.rootTokenHash.Store(&state.RootTokenHash)
	return s.status(state), nil
}

func (s *Service) arm() {
	s.disarm()
	s.generation++
	generation := s.generation
	s.stopExpiry = s.timer.AfterFunc(unsealTimeout, func() { s.expire(generation) })
}

func (s *Service) disarm() {
	if s.stopExpiry != nil {
		s.stopExpiry()
		s.stopExpiry = nil
	}
}

// expire checks the generation because Stop can lose the race with a callback already waiting on the lock.
func (s *Service) expire(generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if generation != s.generation {
		return
	}
	s.keyring.discard()
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

	s.disarm()
	s.keyring.discard()
	return s.status(state), nil
}

const sealResource = "system/seal"

// Seal clears the root token hash, deactivates the resource, then discards buffered shares and clears the key, once
// principal may update system/seal; sealing a sealed instance changes nothing.
func (s *Service) Seal(ctx context.Context, principal authorization.Principal) error {
	// Before the lock: this may read policies, which need not hold up an unseal or reset.
	if err := s.authorizer.Authorize(ctx, principal, sealResource, authorization.CapabilityUpdate); err != nil {
		return fmt.Errorf("system: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// First: no request is root while the seal runs, as when IsRoot waited for it.
	s.rootTokenHash.Store(nil)
	// Before lock: the key is cleared last, so nothing still running can believe it reads storage.
	if s.keyring.unlocked() {
		s.resource.Deactivate()
	}
	s.disarm()
	s.keyring.lock()
	return nil
}

// IsRoot reports whether token is the root token verified at the last unseal, without waiting on one in progress;
// it is false for every token from the start of a seal until an unseal has activated the resource.
func (s *Service) IsRoot(token []byte) bool {
	want := s.rootTokenHash.Load()
	if want == nil {
		return false
	}
	hash := sha256.Sum256(token)
	return subtle.ConstantTimeCompare(hash[:], want[:]) == 1
}

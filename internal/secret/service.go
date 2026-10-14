// Package secret owns secret CRUD and listing; it never encrypts, the repository below it does.
package secret

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// MaxValueSize is the largest secret value accepted, in bytes.
const MaxValueSize = 64 << 10

// MinGeneratedLength is the shortest secret Generate makes, in bytes: 128 bits.
const MinGeneratedLength = 16

// resourcePrefix turns a secret path into the resource policies name it by.
const resourcePrefix = "secrets/"

// Entry is a stored secret.
type Entry struct {
	Value []byte
	// Generated marks a value seal-gate drew itself, so it knows the shape to rotate it to.
	Generated bool
	// TTL is kept so each rotation can set the next expiry; zero is none.
	TTL time.Duration
	// ExpiresAt is when a stored secret stops reading, or a generated one is due for rotation; zero is never.
	ExpiresAt time.Time
}

// expired holds for a stored secret past its lifetime; a generated one past its expiry is due for rotation instead.
func (e Entry) expired(now time.Time) bool {
	return !e.Generated && !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt)
}

// Repository stores secrets by path. Get returns an entry the caller owns, or ErrNotFound for a missing path, and
// Delete does not fail on one; every method returns ErrSealed while sealed.
type Repository interface {
	Put(ctx context.Context, path string, entry Entry) error
	Get(ctx context.Context, path string) (Entry, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// Clock is the time expiry is computed and checked against, so tests can fix it.
type Clock interface {
	Now() time.Time
}

// Random is a source of cryptographically secure random bytes.
type Random interface {
	Bytes(n int) ([]byte, error)
}

// Service validates paths and sizes and authorizes each operation for its principal before the repository serves it.
type Service struct {
	// Every write holds mu, so the read that decides it (existence, the generated mark) sees the state it replaces:
	// a create-only principal cannot overwrite a secret written in between, nor a rotation a value just PUT.
	mu         sync.Mutex
	repo       Repository
	random     Random
	authorizer authorization.Authorizer
	clock      Clock
}

// New returns a Service over repo that draws generated values from random and asks authorizer before every operation.
func New(repo Repository, random Random, authorizer authorization.Authorizer, clock Clock) *Service {
	return &Service{repo: repo, random: random, authorizer: authorizer, clock: clock}
}

// Put stores value at path for ttl, zero meaning no expiry, replacing any secret already there; it asks create when
// path is missing, update when it exists.
func (s *Service) Put(ctx context.Context, principal authorization.Principal, path string, value []byte, ttl time.Duration) error {
	if !validPath(path) {
		return ErrInvalidPath
	}
	if len(value) > MaxValueSize {
		return ErrValueTooLarge
	}
	if ttl < 0 {
		return ErrInvalidTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	capability := authorization.CapabilityUpdate
	old, err := s.current(ctx, path)
	clear(old.Value)
	switch {
	case errors.Is(err, ErrNotFound):
		capability = authorization.CapabilityCreate
	case errors.Is(err, ErrSealed):
		return err
	case err != nil:
		return fmt.Errorf("secret: %w", err)
	}

	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+path, capability); err != nil {
		return fmt.Errorf("secret: %w", err)
	}

	err = s.repo.Put(ctx, path, Entry{Value: value, TTL: ttl, ExpiresAt: s.expiry(ttl)})
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("secret: %w", err)
	}
	return err
}

// Get returns the secret at path; a missing or expired one is ErrNotFound.
func (s *Service) Get(ctx context.Context, principal authorization.Principal, path string) (Entry, error) {
	if !validPath(path) {
		return Entry{}, ErrInvalidPath
	}
	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+path, authorization.CapabilityRead); err != nil {
		return Entry{}, fmt.Errorf("secret: %w", err)
	}

	entry, err := s.current(ctx, path)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrSealed) {
		return Entry{}, fmt.Errorf("secret: %w", err)
	}
	return entry, err
}

// Generate creates a secret of length random bytes at path, marked generated and due for rotation every ttl (zero is
// never), and returns its value; an existing path is ErrExists.
func (s *Service) Generate(ctx context.Context, principal authorization.Principal, path string, length int, ttl time.Duration) ([]byte, error) {
	if !validPath(path) {
		return nil, ErrInvalidPath
	}
	if length < MinGeneratedLength || length > MaxValueSize {
		return nil, ErrInvalidLength
	}
	if ttl < 0 {
		return nil, ErrInvalidTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Before the existence read, so a caller without create never learns whether path exists.
	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+path, authorization.CapabilityCreate); err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	old, err := s.current(ctx, path)
	clear(old.Value)
	switch {
	case err == nil:
		return nil, ErrExists
	case errors.Is(err, ErrSealed):
		return nil, err
	case !errors.Is(err, ErrNotFound):
		return nil, fmt.Errorf("secret: %w", err)
	}

	return s.storeGenerated(ctx, path, length, ttl)
}

// storeGenerated draws length random bytes and stores them at path, marked generated and due after ttl; the caller holds mu.
func (s *Service) storeGenerated(ctx context.Context, path string, length int, ttl time.Duration) ([]byte, error) {
	value, err := s.random.Bytes(length)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	err = s.repo.Put(ctx, path, Entry{Value: value, Generated: true, TTL: ttl, ExpiresAt: s.expiry(ttl)})
	switch {
	case errors.Is(err, ErrSealed):
		clear(value)
		return nil, err
	case err != nil:
		clear(value)
		return nil, fmt.Errorf("secret: %w", err)
	}
	return value, nil
}

// Rotate replaces a generated secret with fresh random bytes of its length, due again one TTL from now, and returns
// them; a secret not generated is ErrNotRotatable.
func (s *Service) Rotate(ctx context.Context, principal authorization.Principal, path string) ([]byte, error) {
	if !validPath(path) {
		return nil, ErrInvalidPath
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Before the read, so a caller without rotate never learns whether path exists.
	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+path, authorization.CapabilityRotate); err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	old, err := s.current(ctx, path)
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrSealed):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("secret: %w", err)
	}
	length := len(old.Value)
	clear(old.Value)
	if !old.Generated {
		return nil, ErrNotRotatable
	}

	return s.storeGenerated(ctx, path, length, old.TTL)
}

// current reads the secret at path as the repository does, except that an expired one is ErrNotFound.
func (s *Service) current(ctx context.Context, path string) (Entry, error) {
	entry, err := s.repo.Get(ctx, path)
	if err == nil && entry.expired(s.clock.Now()) {
		clear(entry.Value)
		return Entry{}, ErrNotFound
	}
	return entry, err
}

// expiry is when a secret written now with ttl expires; zero for no ttl.
func (s *Service) expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.clock.Now().Add(ttl)
}

// Delete removes the secret at path; a missing path is not an error.
func (s *Service) Delete(ctx context.Context, principal authorization.Principal, path string) error {
	if !validPath(path) {
		return ErrInvalidPath
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+path, authorization.CapabilityDelete); err != nil {
		return fmt.Errorf("secret: %w", err)
	}

	err := s.repo.Delete(ctx, path)
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("secret: %w", err)
	}
	return err
}

// List returns the full paths under prefix that have not expired, sorted; prefix is "" or a valid path ending in '/'.
func (s *Service) List(ctx context.Context, principal authorization.Principal, prefix string) ([]string, error) {
	if !validPrefix(prefix) {
		return nil, ErrInvalidPath
	}
	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+prefix, authorization.CapabilityList); err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	paths, err := s.repo.List(ctx, prefix)
	switch {
	case errors.Is(err, ErrSealed):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("secret: %w", err)
	}

	live := make([]string, 0, len(paths))
	for _, path := range paths {
		entry, err := s.current(ctx, path)
		clear(entry.Value)
		switch {
		case errors.Is(err, ErrNotFound):
			continue
		case errors.Is(err, ErrSealed):
			return nil, err
		case err != nil:
			return nil, fmt.Errorf("secret: %w", err)
		}
		live = append(live, path)
	}
	return live, nil
}

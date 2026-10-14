// Package secret owns secret CRUD and listing; it never encrypts, the repository below it does.
package secret

import (
	"context"
	"errors"
	"fmt"
	"sync"

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
}

// Repository stores secrets by path. Get returns an entry the caller owns, or ErrNotFound for a missing path, and
// Delete does not fail on one; every method returns ErrSealed while sealed.
type Repository interface {
	Put(ctx context.Context, path string, entry Entry) error
	Get(ctx context.Context, path string) (Entry, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// Random is a source of cryptographically secure random bytes.
type Random interface {
	Bytes(n int) ([]byte, error)
}

// Service validates paths and sizes and authorizes each operation for its principal before the repository serves it.
type Service struct {
	repo       Repository
	random     Random
	authorizer authorization.Authorizer
	// Every write holds mu, so the existence read and the write see the same state:
	// a create-only principal cannot overwrite a secret written in between.
	mu sync.Mutex
}

// New returns a Service over repo that draws generated values from random and asks authorizer before every operation.
func New(repo Repository, random Random, authorizer authorization.Authorizer) *Service {
	return &Service{repo: repo, random: random, authorizer: authorizer}
}

// Put stores value at path, replacing any secret already there; it asks create when path is missing, update when it exists.
func (s *Service) Put(ctx context.Context, principal authorization.Principal, path string, value []byte) error {
	if !validPath(path) {
		return ErrInvalidPath
	}
	if len(value) > MaxValueSize {
		return ErrValueTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	capability := authorization.CapabilityUpdate
	old, err := s.repo.Get(ctx, path)
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

	err = s.repo.Put(ctx, path, Entry{Value: value})
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("secret: %w", err)
	}
	return err
}

// Get returns the value at path, or ErrNotFound if there is none.
func (s *Service) Get(ctx context.Context, principal authorization.Principal, path string) ([]byte, error) {
	if !validPath(path) {
		return nil, ErrInvalidPath
	}
	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+path, authorization.CapabilityRead); err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	entry, err := s.repo.Get(ctx, path)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrSealed) {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return entry.Value, err
}

// Generate creates a secret of length random bytes at path, marked generated, and returns its value; an existing path is ErrExists.
func (s *Service) Generate(ctx context.Context, principal authorization.Principal, path string, length int) ([]byte, error) {
	if !validPath(path) {
		return nil, ErrInvalidPath
	}
	if length < MinGeneratedLength || length > MaxValueSize {
		return nil, ErrInvalidLength
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Before the existence read, so a caller without create never learns whether path exists.
	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+path, authorization.CapabilityCreate); err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	old, err := s.repo.Get(ctx, path)
	clear(old.Value)
	switch {
	case err == nil:
		return nil, ErrExists
	case errors.Is(err, ErrSealed):
		return nil, err
	case !errors.Is(err, ErrNotFound):
		return nil, fmt.Errorf("secret: %w", err)
	}

	value, err := s.random.Bytes(length)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	err = s.repo.Put(ctx, path, Entry{Value: value, Generated: true})
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

// List returns the full paths under prefix, sorted; prefix is "" or a valid path ending in '/'.
func (s *Service) List(ctx context.Context, principal authorization.Principal, prefix string) ([]string, error) {
	if !validPrefix(prefix) {
		return nil, ErrInvalidPath
	}
	if err := s.authorizer.Authorize(ctx, principal, resourcePrefix+prefix, authorization.CapabilityList); err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	paths, err := s.repo.List(ctx, prefix)
	if err != nil && !errors.Is(err, ErrSealed) {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return paths, err
}

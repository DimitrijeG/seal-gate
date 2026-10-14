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

// resourcePrefix turns a secret path into the resource policies name it by.
const resourcePrefix = "secrets/"

// Repository stores secrets by path. Get returns a slice the caller owns, or ErrNotFound for a missing path, and
// Delete does not fail on one; every method returns ErrSealed while sealed.
type Repository interface {
	Put(ctx context.Context, path string, value []byte) error
	Get(ctx context.Context, path string) ([]byte, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// Service validates paths and sizes and authorizes each operation for its principal before the repository serves it.
type Service struct {
	repo       Repository
	authorizer authorization.Authorizer
	// Every write holds mu, so the existence read and the write see the same state:
	// a create-only principal cannot overwrite a secret written in between.
	mu sync.Mutex
}

// New returns a Service over repo that asks authorizer before every operation.
func New(repo Repository, authorizer authorization.Authorizer) *Service {
	return &Service{repo: repo, authorizer: authorizer}
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
	clear(old)
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

	err = s.repo.Put(ctx, path, value)
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

	value, err := s.repo.Get(ctx, path)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrSealed) {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return value, err
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

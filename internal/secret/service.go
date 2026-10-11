// Package secret owns secret CRUD and listing; it never encrypts, the repository below it does.
package secret

import (
	"context"
	"errors"
	"fmt"
)

// MaxValueSize is the largest secret value accepted, in bytes.
const MaxValueSize = 64 << 10

// Repository stores secrets by path. Get returns ErrNotFound for a missing path and
// Delete does not fail on one; every method returns ErrSealed while sealed.
type Repository interface {
	Put(ctx context.Context, path string, value []byte) error
	Get(ctx context.Context, path string) ([]byte, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// Service validates paths and sizes before they reach the repository.
type Service struct {
	repo Repository
}

// New returns a Service over repo.
func New(repo Repository) *Service {
	return &Service{repo: repo}
}

// Put stores value at path, replacing any secret already there.
func (s *Service) Put(ctx context.Context, path string, value []byte) error {
	if !validPath(path) {
		return ErrInvalidPath
	}
	if len(value) > MaxValueSize {
		return ErrValueTooLarge
	}

	err := s.repo.Put(ctx, path, value)
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("secret: %w", err)
	}
	return err
}

// Get returns the value at path, or ErrNotFound if there is none.
func (s *Service) Get(ctx context.Context, path string) ([]byte, error) {
	if !validPath(path) {
		return nil, ErrInvalidPath
	}

	value, err := s.repo.Get(ctx, path)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrSealed) {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return value, err
}

// Delete removes the secret at path; a missing path is not an error.
func (s *Service) Delete(ctx context.Context, path string) error {
	if !validPath(path) {
		return ErrInvalidPath
	}

	err := s.repo.Delete(ctx, path)
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("secret: %w", err)
	}
	return err
}

// List returns the full paths under prefix, sorted; prefix is "" or a valid path ending in '/'.
func (s *Service) List(ctx context.Context, prefix string) ([]string, error) {
	if !validPrefix(prefix) {
		return nil, ErrInvalidPath
	}

	paths, err := s.repo.List(ctx, prefix)
	if err != nil && !errors.Is(err, ErrSealed) {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return paths, err
}

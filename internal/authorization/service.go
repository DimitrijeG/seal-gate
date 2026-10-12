// Package authorization owns ACL policies: their vocabulary, what makes one valid, and storing them.
package authorization

import (
	"context"
	"errors"
	"fmt"
)

// Repository stores policies by name. Get returns ErrNotFound for a missing name and
// Delete does not fail on one; every method returns ErrSealed while sealed.
type Repository interface {
	Put(ctx context.Context, policy Policy) error
	Get(ctx context.Context, name string) (Policy, error)
	Delete(ctx context.Context, name string) error
}

// Service validates policies and names before they reach the repository.
type Service struct {
	repo Repository
}

// New returns a Service over repo.
func New(repo Repository) *Service {
	return &Service{repo: repo}
}

// Put stores policy under its name, replacing any policy already there.
func (s *Service) Put(ctx context.Context, policy Policy) error {
	if !validName(policy.Name) {
		return ErrInvalidName
	}
	for _, rule := range policy.Rules {
		if !validRule(rule) {
			return ErrInvalidRule
		}
	}

	err := s.repo.Put(ctx, policy)
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("authorization: %w", err)
	}
	return err
}

// Get returns the policy named name, or ErrNotFound if there is none.
func (s *Service) Get(ctx context.Context, name string) (Policy, error) {
	if !validName(name) {
		return Policy{}, ErrInvalidName
	}

	policy, err := s.repo.Get(ctx, name)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrSealed) {
		return Policy{}, fmt.Errorf("authorization: %w", err)
	}
	return policy, err
}

// Delete removes the policy named name; a missing name is not an error.
func (s *Service) Delete(ctx context.Context, name string) error {
	if !validName(name) {
		return ErrInvalidName
	}

	err := s.repo.Delete(ctx, name)
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("authorization: %w", err)
	}
	return err
}

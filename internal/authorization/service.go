// Package authorization owns ACL policies: their vocabulary, what makes one valid, and the access decisions made from them.
package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Repository stores policies by name. Get returns ErrNotFound for a missing name and ErrUnreadablePolicy
// for a corrupt record; Delete does not fail on a missing name; every method returns ErrSealed while sealed.
type Repository interface {
	Put(ctx context.Context, policy Policy) error
	Get(ctx context.Context, name string) (Policy, error)
	Delete(ctx context.Context, name string) error
}

// Service manages policies, validating them before they reach the repository, and decides access from them.
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

// Get returns the policy named name; ErrNotFound if there is none, ErrUnreadablePolicy if its record or any rule in it is invalid.
func (s *Service) Get(ctx context.Context, name string) (Policy, error) {
	if !validName(name) {
		return Policy{}, ErrInvalidName
	}

	policy, err := s.repo.Get(ctx, name)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrSealed) && !errors.Is(err, ErrUnreadablePolicy) {
		return Policy{}, fmt.Errorf("authorization: %w", err)
	}
	if err != nil {
		return Policy{}, err
	}

	// Checked again on read: an invalid deny rule would grant nothing, so a corrupt record would widen access.
	for _, rule := range policy.Rules {
		if !validRule(rule) {
			return Policy{}, ErrUnreadablePolicy
		}
	}
	return policy, nil
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

// Authorize returns nil if principal may use capability on resource, else ErrDenied: the root always may, others
// when one of their policies grants it and none denies it. A missing policy grants nothing; any other read failure is returned as is.
func (s *Service) Authorize(ctx context.Context, principal Principal, resource string, capability Capability) error {
	if principal.root {
		return nil
	}

	var granted, denied bool

	// Deny wins over any grant, so every matching rule is seen before deciding.
	for _, name := range principal.policies {
		policy, err := s.Get(ctx, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}

		for _, rule := range policy.Rules {
			if !matches(rule.Path, resource) {
				continue
			}

			if slices.Contains(rule.Capabilities, CapabilityDeny) {
				denied = true
			}
			if slices.Contains(rule.Capabilities, capability) {
				granted = true
			}
		}
	}

	if granted && !denied {
		return nil
	}
	return ErrDenied
}

func matches(pattern, resource string) bool {
	if prefix, starred := strings.CutSuffix(pattern, "*"); starred {
		return strings.HasPrefix(resource, prefix)
	}
	return pattern == resource
}

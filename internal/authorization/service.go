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
// for a corrupt record; Delete does not fail on a missing name; List returns every name in byte order;
// every method returns ErrSealed while sealed.
type Repository interface {
	Put(ctx context.Context, policy Policy) error
	Get(ctx context.Context, name string) (Policy, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]string, error)
}

// Authorizer decides whether principal may use capability on resource: nil allows, ErrDenied refuses, any other error means no decision.
type Authorizer interface {
	Authorize(ctx context.Context, principal Principal, resource string, capability Capability) error
}

var _ Authorizer = (*Service)(nil)

const (
	// policiesResource is the resource policies name the policy collection by.
	policiesResource = "system/policies"
	// policyResourcePrefix turns a policy name into the resource policies name it by.
	policyResourcePrefix = policiesResource + "/"
)

// Service manages policies, validating each and authorizing its principal before the repository, and decides access from them.
type Service struct {
	repo Repository
}

// New returns a Service over repo.
func New(repo Repository) *Service {
	return &Service{repo: repo}
}

// Put stores policy under its name, replacing any policy already there; principal needs update on it, whether or not it exists.
func (s *Service) Put(ctx context.Context, principal Principal, policy Policy) error {
	if !validName(policy.Name) {
		return ErrInvalidName
	}
	for _, rule := range policy.Rules {
		if !validRule(rule) {
			return ErrInvalidRule
		}
	}
	if err := s.Authorize(ctx, principal, policyResourcePrefix+policy.Name, CapabilityUpdate); err != nil {
		return err
	}

	err := s.repo.Put(ctx, policy)
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("authorization: %w", err)
	}
	return err
}

// Get returns the policy named name if principal may read it; ErrNotFound if there is none, ErrUnreadablePolicy if its record or any rule in it is invalid.
func (s *Service) Get(ctx context.Context, principal Principal, name string) (Policy, error) {
	if !validName(name) {
		return Policy{}, ErrInvalidName
	}
	if err := s.Authorize(ctx, principal, policyResourcePrefix+name, CapabilityRead); err != nil {
		return Policy{}, err
	}

	return s.get(ctx, name)
}

// get reads without authorizing, since Authorize reads through it and would otherwise ask itself forever.
func (s *Service) get(ctx context.Context, name string) (Policy, error) {
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

// Delete removes the policy named name if principal may delete it; a missing name is not an error.
func (s *Service) Delete(ctx context.Context, principal Principal, name string) error {
	if !validName(name) {
		return ErrInvalidName
	}
	if err := s.Authorize(ctx, principal, policyResourcePrefix+name, CapabilityDelete); err != nil {
		return err
	}

	err := s.repo.Delete(ctx, name)
	if err != nil && !errors.Is(err, ErrSealed) {
		return fmt.Errorf("authorization: %w", err)
	}
	return err
}

// List returns every policy's name in byte order if principal may list the policy collection.
func (s *Service) List(ctx context.Context, principal Principal) ([]string, error) {
	if err := s.Authorize(ctx, principal, policiesResource, CapabilityList); err != nil {
		return nil, err
	}

	names, err := s.repo.List(ctx)
	if err != nil && !errors.Is(err, ErrSealed) {
		return nil, fmt.Errorf("authorization: %w", err)
	}
	return names, err
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
		policy, err := s.get(ctx, name)
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

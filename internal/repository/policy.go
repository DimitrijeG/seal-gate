package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

// policyRepository stores policies through the barrier, one key per policy.
type policyRepository struct {
	encrypted *barrier.AEADBarrier
}

var _ authorization.Repository = (*policyRepository)(nil)

const (
	policyRecordVersion = 1
	// Every barrier key starts with its domain's prefix,
	// never sys/, so no path reaches the system records.
	policyPrefix = "policies/"
)

// policyRecord is the stored layout; it changes only with its version. The name is the key, not a field.
type policyRecord struct {
	Version int          `json:"version"`
	Rules   []ruleRecord `json:"rules"`
}

type ruleRecord struct {
	Path         string                     `json:"path"`
	Capabilities []authorization.Capability `json:"capabilities"`
}

func policyKey(name string) string {
	return policyPrefix + name
}

func (r *policyRepository) Put(ctx context.Context, policy authorization.Policy) error {
	encoded, err := json.Marshal(toPolicyRecord(policy))
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}

	err = r.encrypted.Put(ctx, policyKey(policy.Name), encoded)
	if errors.Is(err, barrier.ErrSealed) {
		return authorization.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *policyRepository) Get(ctx context.Context, name string) (authorization.Policy, error) {
	encoded, err := r.encrypted.Get(ctx, policyKey(name))
	if errors.Is(err, barrier.ErrSealed) {
		return authorization.Policy{}, authorization.ErrSealed
	}
	if errors.Is(err, storage.ErrNotFound) {
		return authorization.Policy{}, authorization.ErrNotFound
	}
	if err != nil {
		return authorization.Policy{}, fmt.Errorf("repository: %w", err)
	}

	var record policyRecord
	// The decode error is replaced, not wrapped: as a *json.SyntaxError it would
	// reach the client as a 400 about its own request body.
	if err := json.Unmarshal(encoded, &record); err != nil {
		return authorization.Policy{}, authorization.ErrUnreadablePolicy
	}
	if record.Version != policyRecordVersion {
		return authorization.Policy{}, authorization.ErrUnreadablePolicy
	}
	return record.policy(name), nil
}

func (r *policyRepository) Delete(ctx context.Context, name string) error {
	err := r.encrypted.Delete(ctx, policyKey(name))
	if errors.Is(err, barrier.ErrSealed) {
		return authorization.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *policyRepository) List(ctx context.Context) ([]string, error) {
	names, err := listNames(ctx, r.encrypted, policyPrefix)
	if errors.Is(err, barrier.ErrSealed) {
		return nil, authorization.ErrSealed
	}
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	return names, nil
}

func toPolicyRecord(policy authorization.Policy) policyRecord {
	rules := make([]ruleRecord, len(policy.Rules))
	for i, rule := range policy.Rules {
		rules[i] = ruleRecord{Path: rule.Path, Capabilities: rule.Capabilities}
	}
	return policyRecord{
		Version: policyRecordVersion,
		Rules:   rules,
	}
}

func (r policyRecord) policy(name string) authorization.Policy {
	rules := make([]authorization.Rule, len(r.Rules))
	for i, rule := range r.Rules {
		rules[i] = authorization.Rule{Path: rule.Path, Capabilities: rule.Capabilities}
	}
	return authorization.Policy{
		Name:  name,
		Rules: rules,
	}
}

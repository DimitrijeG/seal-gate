package authorization_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// fakeRepository keeps policies in a map; err, when set, fails every call.
type fakeRepository struct {
	policies map[string]authorization.Policy
	calls    int
	err      error
}

func (r *fakeRepository) Put(_ context.Context, policy authorization.Policy) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.policies[policy.Name] = policy
	return nil
}

func (r *fakeRepository) Get(_ context.Context, name string) (authorization.Policy, error) {
	r.calls++
	if r.err != nil {
		return authorization.Policy{}, r.err
	}
	policy, ok := r.policies[name]
	if !ok {
		return authorization.Policy{}, authorization.ErrNotFound
	}
	return policy, nil
}

func (r *fakeRepository) Delete(_ context.Context, name string) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	delete(r.policies, name)
	return nil
}

// root passes every check, so tests about storing policies are not about access.
var root = authorization.NewRootPrincipal()

func newService(t *testing.T) (*authorization.Service, *fakeRepository) {
	t.Helper()
	repo := &fakeRepository{policies: make(map[string]authorization.Policy)}
	return authorization.New(repo), repo
}

func TestService(t *testing.T) {
	t.Run("a stored policy reads back", func(t *testing.T) {
		s, _ := newService(t)
		policy := authorization.Policy{
			Name: "dev",
			Rules: []authorization.Rule{{
				Path:         "secrets/dev/*",
				Capabilities: []authorization.Capability{authorization.CapabilityRead, authorization.CapabilityList},
			}},
		}

		if err := s.Put(t.Context(), root, policy); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(t.Context(), root, "dev")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !reflect.DeepEqual(got, policy) {
			t.Errorf("got %+v, want %+v", got, policy)
		}
	})

	t.Run("reading a missing policy is not found", func(t *testing.T) {
		s, _ := newService(t)

		_, err := s.Get(t.Context(), root, "missing")

		if !errors.Is(err, authorization.ErrNotFound) {
			t.Errorf("got %v, want %v", err, authorization.ErrNotFound)
		}
	})

	t.Run("a deleted policy is not found", func(t *testing.T) {
		s, _ := newService(t)

		if err := s.Put(t.Context(), root, authorization.Policy{Name: "dev"}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Delete(t.Context(), root, "dev"); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		_, err := s.Get(t.Context(), root, "dev")
		if !errors.Is(err, authorization.ErrNotFound) {
			t.Errorf("got %v, want %v", err, authorization.ErrNotFound)
		}
	})

	t.Run("an invalid name is refused", func(t *testing.T) {
		tests := []struct {
			name       string
			policyName string
		}{
			{"empty", ""},
			{"slash", "dev/ops"},
			{"dot", "."},
			{"dot-dot", ".."},
			{"wildcard", "dev*"},
			{"space", "dev ops"},
			{"non-ASCII letter", "dév"},
			{"over 128 bytes", strings.Repeat("a", 129)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				err := s.Put(t.Context(), root, authorization.Policy{Name: tt.policyName})

				if !errors.Is(err, authorization.ErrInvalidName) {
					t.Errorf("got %v, want %v", err, authorization.ErrInvalidName)
				}
			})
		}
	})

	t.Run("a valid name is accepted", func(t *testing.T) {
		tests := []struct {
			name       string
			policyName string
		}{
			{"every allowed character", "Az09._-"},
			{"leading dot", ".ops"},
			{"three dots", "..."},
			{"exactly 128 bytes", strings.Repeat("a", 128)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				if err := s.Put(t.Context(), root, authorization.Policy{Name: tt.policyName}); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("every operation refuses an invalid name before the repository", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *authorization.Service) error
		}{
			{"put", func(ctx context.Context, s *authorization.Service) error {
				return s.Put(ctx, root, authorization.Policy{Name: "dev/ops"})
			}},
			{"get", func(ctx context.Context, s *authorization.Service) error {
				_, err := s.Get(ctx, root, "dev/ops")
				return err
			}},
			{"delete", func(ctx context.Context, s *authorization.Service) error {
				return s.Delete(ctx, root, "dev/ops")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo := newService(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, authorization.ErrInvalidName) {
					t.Errorf("err: got %v, want %v", err, authorization.ErrInvalidName)
				}
				if repo.calls != 0 {
					t.Errorf("calls: got %d, want 0", repo.calls)
				}
			})
		}
	})

	t.Run("a rule with an invalid path pattern is refused", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
		}{
			{"empty", ""},
			{"wildcard mid-path", "secrets/*/x"},
			{"double wildcard", "**"},
			{"leading wildcard", "*secrets"},
			{"leading slash", "/secrets"},
			{"trailing slash", "secrets/"},
			{"empty segment", "secrets//db"},
			{"dot-dot segment", "secrets/../system"},
			{"non-ASCII letter", "secrets/dév"},
			{"over 257 bytes", strings.Repeat("a", 258)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				err := s.Put(t.Context(), root, policyWithRule(tt.pattern, authorization.CapabilityRead))

				if !errors.Is(err, authorization.ErrInvalidRule) {
					t.Errorf("got %v, want %v", err, authorization.ErrInvalidRule)
				}
			})
		}
	})

	t.Run("a valid path pattern is accepted", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
		}{
			{"exact", "secrets/db/password"},
			{"prefix after a slash", "secrets/db/*"},
			{"prefix mid-segment", "secrets/db*"},
			{"wildcard alone", "*"},
			{"exactly 257 bytes", strings.Repeat("a", 256) + "*"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				if err := s.Put(t.Context(), root, policyWithRule(tt.pattern, authorization.CapabilityRead)); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a rule with an unknown capability is refused", func(t *testing.T) {
		tests := []struct {
			name       string
			capability authorization.Capability
		}{
			{"unknown word", "write"},
			{"empty", ""},
			{"wrong case", "Read"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				err := s.Put(t.Context(), root, policyWithRule("secrets/*", tt.capability))

				if !errors.Is(err, authorization.ErrInvalidRule) {
					t.Errorf("got %v, want %v", err, authorization.ErrInvalidRule)
				}
			})
		}
	})

	t.Run("a rule with no capabilities is refused", func(t *testing.T) {
		tests := []struct {
			name         string
			capabilities []authorization.Capability
		}{
			{"nil", nil},
			{"empty", []authorization.Capability{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				err := s.Put(t.Context(), root, policyWithRule("secrets/*", tt.capabilities...))

				if !errors.Is(err, authorization.ErrInvalidRule) {
					t.Errorf("got %v, want %v", err, authorization.ErrInvalidRule)
				}
			})
		}
	})

	t.Run("a rule may hold every capability, deny included", func(t *testing.T) {
		s, _ := newService(t)
		policy := policyWithRule("secrets/*",
			authorization.CapabilityCreate, authorization.CapabilityRead, authorization.CapabilityUpdate,
			authorization.CapabilityDelete, authorization.CapabilityList, authorization.CapabilityRotate,
			authorization.CapabilityManage, authorization.CapabilityDeny)

		if err := s.Put(t.Context(), root, policy); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a policy with no rules is accepted", func(t *testing.T) {
		tests := []struct {
			name  string
			rules []authorization.Rule
		}{
			{"nil", nil},
			{"empty", []authorization.Rule{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				if err := s.Put(t.Context(), root, authorization.Policy{Name: "dev", Rules: tt.rules}); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("an invalid rule never reaches the repository", func(t *testing.T) {
		s, repo := newService(t)

		err := s.Put(t.Context(), root, policyWithRule("secrets/", authorization.CapabilityRead))

		if !errors.Is(err, authorization.ErrInvalidRule) {
			t.Errorf("err: got %v, want %v", err, authorization.ErrInvalidRule)
		}
		if repo.calls != 0 {
			t.Errorf("calls: got %d, want 0", repo.calls)
		}
	})

	t.Run("a stored rule that is not valid is unreadable", func(t *testing.T) {
		tests := []struct {
			name   string
			policy authorization.Policy
		}{
			{"no capabilities", policyWithRule("secrets/*")},
			{"unknown capability", policyWithRule("secrets/*", "sudo")},
			{"invalid pattern", policyWithRule("secrets/*/db", authorization.CapabilityDeny)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo := newService(t)
				// Seeded past Put, as a record from a faulty encoder would arrive.
				repo.policies[tt.policy.Name] = tt.policy

				_, err := s.Get(t.Context(), root, tt.policy.Name)

				if !errors.Is(err, authorization.ErrUnreadablePolicy) {
					t.Errorf("got %v, want %v", err, authorization.ErrUnreadablePolicy)
				}
			})
		}
	})

	t.Run("every operation reports sealed", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, repo := newService(t)
				repo.err = authorization.ErrSealed

				err := op.call(t.Context(), s)

				if !errors.Is(err, authorization.ErrSealed) {
					t.Errorf("got %v, want %v", err, authorization.ErrSealed)
				}
			})
		}
	})

	t.Run("an unexpected repository failure reaches the caller", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, repo := newService(t)
				repoErr := errors.New("disk failed")
				repo.err = repoErr

				err := op.call(t.Context(), s)

				if !errors.Is(err, repoErr) {
					t.Errorf("got %v, want %v", err, repoErr)
				}
			})
		}
	})
}

// operations calls each service method with valid input, so only the repository can fail it.
var operations = []struct {
	name string
	call func(ctx context.Context, s *authorization.Service) error
}{
	{"put", func(ctx context.Context, s *authorization.Service) error {
		return s.Put(ctx, root, policyWithRule("secrets/*", authorization.CapabilityRead))
	}},
	{"get", func(ctx context.Context, s *authorization.Service) error {
		_, err := s.Get(ctx, root, "dev")
		return err
	}},
	{"delete", func(ctx context.Context, s *authorization.Service) error {
		return s.Delete(ctx, root, "dev")
	}},
}

func policyWithRule(pattern string, capabilities ...authorization.Capability) authorization.Policy {
	return authorization.Policy{
		Name:  "dev",
		Rules: []authorization.Rule{{Path: pattern, Capabilities: capabilities}},
	}
}

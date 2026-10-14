package authorization_test

import (
	"errors"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

func newAuthorizer(t *testing.T, policies ...authorization.Policy) (*authorization.Service, *fakeRepository) {
	t.Helper()
	s, repo := newService(t)
	for _, policy := range policies {
		repo.policies[policy.Name] = policy
	}
	return s, repo
}

func TestAuthorize(t *testing.T) {
	t.Run("the root is allowed whatever the resource and capability", func(t *testing.T) {
		tests := []struct {
			name       string
			resource   string
			capability authorization.Capability
		}{
			{"secret read", "secrets/db/password", authorization.CapabilityRead},
			{"system update", "system/seal", authorization.CapabilityUpdate},
			{"a capability no rule can grant", "secrets/db", authorization.CapabilityDeny},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t)

				err := s.Authorize(t.Context(), authorization.NewRootPrincipal(), tt.resource, tt.capability)

				if err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("the root is allowed without reading a policy", func(t *testing.T) {
		s, repo := newAuthorizer(t)
		repo.err = authorization.ErrSealed

		err := s.Authorize(t.Context(), authorization.NewRootPrincipal(), "secrets/db", authorization.CapabilityRead)

		if err != nil {
			t.Errorf("err: got %v, want nil", err)
		}
		if repo.calls != 0 {
			t.Errorf("calls: got %d, want 0", repo.calls)
		}
	})

	t.Run("the zero principal is denied", func(t *testing.T) {
		s, _ := newAuthorizer(t, policyWithRule("*", authorization.CapabilityRead))

		err := s.Authorize(t.Context(), authorization.Principal{}, "secrets/db", authorization.CapabilityRead)

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("got %v, want %v", err, authorization.ErrDenied)
		}
	})

	t.Run("the principal keeps its own copy of the names", func(t *testing.T) {
		s, _ := newAuthorizer(t, policyWithRule("secrets/*", authorization.CapabilityRead))
		names := []string{"dev"}
		principal := authorization.NewEntityPrincipal(entityID, names...)
		names[0] = "missing"

		err := s.Authorize(t.Context(), principal, "secrets/db", authorization.CapabilityRead)

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("no policies is denied", func(t *testing.T) {
		s, _ := newAuthorizer(t)

		err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID), "secrets/db", authorization.CapabilityRead)

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("got %v, want %v", err, authorization.ErrDenied)
		}
	})

	t.Run("an exact pattern grants its capability on that resource", func(t *testing.T) {
		s, _ := newAuthorizer(t, policyWithRule("secrets/db/password", authorization.CapabilityRead))

		err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), "secrets/db/password", authorization.CapabilityRead)

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("an exact pattern does not grant another capability", func(t *testing.T) {
		s, _ := newAuthorizer(t, policyWithRule("secrets/db/password", authorization.CapabilityRead))

		err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), "secrets/db/password", authorization.CapabilityUpdate)

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("got %v, want %v", err, authorization.ErrDenied)
		}
	})

	t.Run("an exact pattern does not match another resource", func(t *testing.T) {
		tests := []struct {
			name     string
			resource string
		}{
			{"longer", "secrets/db/password/x"},
			{"shorter", "secrets/db"},
			{"sibling", "secrets/db/username"},
			{"prefix of the last segment", "secrets/db/pass"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, policyWithRule("secrets/db/password", authorization.CapabilityRead))

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), tt.resource, authorization.CapabilityRead)

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("got %v, want %v", err, authorization.ErrDenied)
				}
			})
		}
	})

	t.Run("a trailing wildcard matches everything under its prefix", func(t *testing.T) {
		tests := []struct {
			name     string
			pattern  string
			resource string
		}{
			{"child", "secrets/db/*", "secrets/db/password"},
			{"deeper", "secrets/db/*", "secrets/db/a/b"},
			{"mid-segment", "secrets/db*", "secrets/dbx"},
			{"mid-segment, the prefix itself", "secrets/db*", "secrets/db"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, policyWithRule(tt.pattern, authorization.CapabilityRead))

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), tt.resource, authorization.CapabilityRead)

				if err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a trailing wildcard does not match outside its prefix", func(t *testing.T) {
		tests := []struct {
			name     string
			resource string
		}{
			{"the prefix's parent", "secrets/db"},
			{"a sibling with the same start", "secrets/dbx/a"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, policyWithRule("secrets/db/*", authorization.CapabilityRead))

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), tt.resource, authorization.CapabilityRead)

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("got %v, want %v", err, authorization.ErrDenied)
				}
			})
		}
	})

	t.Run("a bare wildcard matches every resource", func(t *testing.T) {
		tests := []struct {
			name     string
			resource string
		}{
			{"secret", "secrets/db/password"},
			{"system", "system/policies/dev"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, policyWithRule("*", authorization.CapabilityRead))

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), tt.resource, authorization.CapabilityRead)

				if err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("grants combine", func(t *testing.T) {
		tests := []struct {
			name     string
			policies []authorization.Policy
			names    []string
		}{
			{"two rules in one policy", []authorization.Policy{{
				Name: "dev",
				Rules: []authorization.Rule{
					{Path: "secrets/*", Capabilities: []authorization.Capability{authorization.CapabilityRead}},
					{Path: "secrets/db/*", Capabilities: []authorization.Capability{authorization.CapabilityUpdate}},
				},
			}}, []string{"dev"}},
			{"two policies", []authorization.Policy{
				policyWithRule("secrets/*", authorization.CapabilityRead),
				{Name: "ops", Rules: []authorization.Rule{
					{Path: "secrets/*", Capabilities: []authorization.Capability{authorization.CapabilityUpdate}},
				}},
			}, []string{"dev", "ops"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, tt.policies...)

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, tt.names...), "secrets/db/x", authorization.CapabilityUpdate)

				if err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a matching deny wins over a grant", func(t *testing.T) {
		dev := policyWithRule("secrets/*", authorization.CapabilityRead)
		ops := authorization.Policy{Name: "ops", Rules: []authorization.Rule{
			{Path: "secrets/*", Capabilities: []authorization.Capability{authorization.CapabilityDeny}},
		}}
		tests := []struct {
			name     string
			policies []authorization.Policy
			names    []string
		}{
			{"in the same rule", []authorization.Policy{
				policyWithRule("secrets/*", authorization.CapabilityRead, authorization.CapabilityDeny),
			}, []string{"dev"}},
			{"deny policy named last", []authorization.Policy{dev, ops}, []string{"dev", "ops"}},
			{"deny policy named first", []authorization.Policy{dev, ops}, []string{"ops", "dev"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, tt.policies...)

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, tt.names...), "secrets/db", authorization.CapabilityRead)

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("got %v, want %v", err, authorization.ErrDenied)
				}
			})
		}
	})

	t.Run("a deny on a rule that does not match changes nothing", func(t *testing.T) {
		s, _ := newAuthorizer(t, authorization.Policy{Name: "dev", Rules: []authorization.Rule{
			{Path: "secrets/*", Capabilities: []authorization.Capability{authorization.CapabilityRead}},
			{Path: "secrets/other/*", Capabilities: []authorization.Capability{authorization.CapabilityDeny}},
		}})

		err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), "secrets/db", authorization.CapabilityRead)

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a capability no rule can grant is denied", func(t *testing.T) {
		tests := []struct {
			name       string
			capability authorization.Capability
		}{
			{"deny", authorization.CapabilityDeny},
			{"unknown", "write"},
			{"empty", ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, policyWithRule("secrets/*", authorization.CapabilityRead, authorization.CapabilityDeny))

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), "secrets/db", tt.capability)

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("got %v, want %v", err, authorization.ErrDenied)
				}
			})
		}
	})

	t.Run("a named policy that does not exist grants nothing", func(t *testing.T) {
		tests := []struct {
			name  string
			names []string
			want  error
		}{
			{"alone", []string{"missing"}, authorization.ErrDenied},
			{"beside a grant", []string{"missing", "dev"}, nil},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, policyWithRule("secrets/*", authorization.CapabilityRead))

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, tt.names...), "secrets/db", authorization.CapabilityRead)

				if !errors.Is(err, tt.want) {
					t.Errorf("got %v, want %v", err, tt.want)
				}
			})
		}
	})

	t.Run("a policy that cannot be read fails the decision", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
		}{
			{"sealed", authorization.ErrSealed},
			{"storage error", errors.New("disk failed")},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo := newAuthorizer(t, policyWithRule("secrets/*", authorization.CapabilityRead))
				repo.err = tt.err

				err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"), "secrets/db", authorization.CapabilityRead)

				if !errors.Is(err, tt.err) {
					t.Errorf("got %v, want %v", err, tt.err)
				}
			})
		}
	})

	t.Run("a corrupt deny fails the decision rather than being ignored", func(t *testing.T) {
		grant := policyWithRule("secrets/*", authorization.CapabilityRead)
		grant.Name = "grant"
		// A deny whose capabilities were lost: skipped, it would let the grant through.
		corrupt := policyWithRule("secrets/*")
		s, _ := newAuthorizer(t, grant, corrupt)

		err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "grant", "dev"), "secrets/db", authorization.CapabilityRead)

		if !errors.Is(err, authorization.ErrUnreadablePolicy) {
			t.Errorf("got %v, want %v", err, authorization.ErrUnreadablePolicy)
		}
	})

	t.Run("an invalid policy name is refused before the repository", func(t *testing.T) {
		s, repo := newAuthorizer(t)

		err := s.Authorize(t.Context(), authorization.NewEntityPrincipal(entityID, "dev/ops"), "secrets/db", authorization.CapabilityRead)

		if !errors.Is(err, authorization.ErrInvalidName) {
			t.Errorf("err: got %v, want %v", err, authorization.ErrInvalidName)
		}
		if repo.calls != 0 {
			t.Errorf("calls: got %d, want 0", repo.calls)
		}
	})
}

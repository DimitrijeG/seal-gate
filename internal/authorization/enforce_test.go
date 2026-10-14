package authorization_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// admin is the principal's own policy; ops is the policy it operates on.
func admin(pattern string, capabilities ...authorization.Capability) authorization.Policy {
	policy := policyWithRule(pattern, capabilities...)
	policy.Name = "admin"
	return policy
}

var ops = authorization.Policy{Name: "ops"}

func TestEnforcement(t *testing.T) {
	t.Run("get is denied without read on the policy's resource", func(t *testing.T) {
		tests := []struct {
			name     string
			policies []authorization.Policy
		}{
			{"existing", []authorization.Policy{admin("secrets/*", authorization.CapabilityRead), ops}},
			// Denied, not not-found: the refusal must not reveal whether the policy exists.
			{"missing", []authorization.Policy{admin("secrets/*", authorization.CapabilityRead)}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, tt.policies...)

				_, err := s.Get(t.Context(), authorization.NewEntityPrincipal(entityID, "admin"), "ops")

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("got %v, want %v", err, authorization.ErrDenied)
				}
			})
		}
	})

	t.Run("put and delete are denied without their capability", func(t *testing.T) {
		tests := []struct {
			name    string
			granted []authorization.Capability
			call    func(ctx context.Context, s *authorization.Service, principal authorization.Principal) error
		}{
			{"put", allBut(authorization.CapabilityUpdate), func(ctx context.Context, s *authorization.Service, principal authorization.Principal) error {
				return s.Put(ctx, principal, ops)
			}},
			{"delete", allBut(authorization.CapabilityDelete), func(ctx context.Context, s *authorization.Service, principal authorization.Principal) error {
				return s.Delete(ctx, principal, "ops")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, admin("system/policies/*", tt.granted...))

				err := tt.call(t.Context(), s, authorization.NewEntityPrincipal(entityID, "admin"))

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("got %v, want %v", err, authorization.ErrDenied)
				}
			})
		}
	})

	t.Run("each operation is allowed by its capability on the policy's resource", func(t *testing.T) {
		tests := []struct {
			name       string
			capability authorization.Capability
			stored     []authorization.Policy
			call       func(ctx context.Context, s *authorization.Service, principal authorization.Principal) error
		}{
			{"get", authorization.CapabilityRead, []authorization.Policy{ops}, func(ctx context.Context, s *authorization.Service, principal authorization.Principal) error {
				_, err := s.Get(ctx, principal, "ops")
				return err
			}},
			// ops is missing, yet put asks update, not create.
			{"put", authorization.CapabilityUpdate, nil, func(ctx context.Context, s *authorization.Service, principal authorization.Principal) error {
				return s.Put(ctx, principal, ops)
			}},
			{"delete", authorization.CapabilityDelete, []authorization.Policy{ops}, func(ctx context.Context, s *authorization.Service, principal authorization.Principal) error {
				return s.Delete(ctx, principal, "ops")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, append(tt.stored, admin("system/policies/ops", tt.capability))...)

				if err := tt.call(t.Context(), s, authorization.NewEntityPrincipal(entityID, "admin")); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("an invalid name is refused before authorizing", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *authorization.Service) error
		}{
			{"put", func(ctx context.Context, s *authorization.Service) error {
				return s.Put(ctx, authorization.Principal{}, authorization.Policy{Name: "dev/ops"})
			}},
			{"get", func(ctx context.Context, s *authorization.Service) error {
				_, err := s.Get(ctx, authorization.Principal{}, "dev/ops")
				return err
			}},
			{"delete", func(ctx context.Context, s *authorization.Service) error {
				return s.Delete(ctx, authorization.Principal{}, "dev/ops")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, authorization.ErrInvalidName) {
					t.Errorf("got %v, want %v", err, authorization.ErrInvalidName)
				}
			})
		}
	})
}

// allBut returns every granting capability but except; deny is left out, since it would refuse whatever else is granted.
func allBut(except authorization.Capability) []authorization.Capability {
	all := []authorization.Capability{
		authorization.CapabilityCreate, authorization.CapabilityRead, authorization.CapabilityUpdate,
		authorization.CapabilityDelete, authorization.CapabilityList, authorization.CapabilityRotate,
		authorization.CapabilityManage,
	}
	return slices.DeleteFunc(all, func(c authorization.Capability) bool { return c == except })
}

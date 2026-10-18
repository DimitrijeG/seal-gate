package authorization_test

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

func TestRules(t *testing.T) {
	t.Run("a principal's rules are its policy's rules", func(t *testing.T) {
		policy := policyWithRule("secrets/*", authorization.CapabilityRead)
		s, _ := newAuthorizer(t, policy)

		got, err := s.Rules(t.Context(), authorization.NewEntityPrincipal(entityID, "dev"))

		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		if want := (authorization.Grants{Rules: policy.Rules}); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("rules from several policies come back in policy order", func(t *testing.T) {
		dev := policyWithRule("secrets/dev/*", authorization.CapabilityRead)
		ops := authorization.Policy{Name: "ops", Rules: []authorization.Rule{
			{Path: "secrets/ops/*", Capabilities: []authorization.Capability{authorization.CapabilityList}},
		}}
		s, _ := newAuthorizer(t, dev, ops)

		got, err := s.Rules(t.Context(), authorization.NewEntityPrincipal(entityID, "ops", "dev"))

		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		want := authorization.Grants{Rules: append(slices.Clone(ops.Rules), dev.Rules...)}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("rules on the same path are kept apart", func(t *testing.T) {
		dev := policyWithRule("secrets/*", authorization.CapabilityRead)
		ops := authorization.Policy{Name: "ops", Rules: []authorization.Rule{
			{Path: "secrets/*", Capabilities: []authorization.Capability{authorization.CapabilityDeny}},
		}}
		s, _ := newAuthorizer(t, dev, ops)

		got, err := s.Rules(t.Context(), authorization.NewEntityPrincipal(entityID, "dev", "ops"))

		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		want := authorization.Grants{Rules: append(slices.Clone(dev.Rules), ops.Rules...)}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a named policy that does not exist contributes no rules", func(t *testing.T) {
		dev := policyWithRule("secrets/*", authorization.CapabilityRead)
		tests := []struct {
			name  string
			names []string
			want  authorization.Grants
		}{
			{"alone", []string{"missing"}, authorization.Grants{}},
			{"beside a policy", []string{"missing", "dev"}, authorization.Grants{Rules: dev.Rules}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newAuthorizer(t, dev)

				got, err := s.Rules(t.Context(), authorization.NewEntityPrincipal(entityID, tt.names...))

				if err != nil {
					t.Fatalf("Rules: %v", err)
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("got %+v, want %+v", got, tt.want)
				}
			})
		}
	})

	t.Run("a policy that cannot be read fails the rules", func(t *testing.T) {
		ops := authorization.Policy{Name: "ops", Rules: []authorization.Rule{
			{Path: "secrets/ops/*", Capabilities: []authorization.Capability{authorization.CapabilityRead}},
		}}
		storageErr := errors.New("disk failed")
		tests := []struct {
			name    string
			dev     authorization.Policy
			names   []string
			repoErr error
			want    error
		}{
			{"sealed", policyWithRule("secrets/*", authorization.CapabilityRead), []string{"dev"}, authorization.ErrSealed, authorization.ErrSealed},
			{"storage error", policyWithRule("secrets/*", authorization.CapabilityRead), []string{"dev"}, storageErr, storageErr},
			{"unreadable record", policyWithRule("secrets/*", authorization.CapabilityRead), []string{"dev"}, authorization.ErrUnreadablePolicy, authorization.ErrUnreadablePolicy},
			{"corrupt rule", policyWithRule("secrets/*"), []string{"ops", "dev"}, nil, authorization.ErrUnreadablePolicy},
			{"invalid name", policyWithRule("secrets/*", authorization.CapabilityRead), []string{"ops", "dev/ops"}, nil, authorization.ErrInvalidName},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo := newAuthorizer(t, ops, tt.dev)
				repo.err = tt.repoErr

				got, err := s.Rules(t.Context(), authorization.NewEntityPrincipal(entityID, tt.names...))

				if !errors.Is(err, tt.want) {
					t.Errorf("err: got %v, want %v", err, tt.want)
				}
				if !reflect.DeepEqual(got, authorization.Grants{}) {
					t.Errorf("grants: got %+v, want none", got)
				}
			})
		}
	})

	t.Run("the root principal is reported as root", func(t *testing.T) {
		s, _ := newAuthorizer(t)

		got, err := s.Rules(t.Context(), authorization.NewRootPrincipal())

		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		if want := (authorization.Grants{Root: true}); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the zero principal has no rules", func(t *testing.T) {
		s, _ := newAuthorizer(t, policyWithRule("*", authorization.CapabilityRead))

		got, err := s.Rules(t.Context(), authorization.Principal{})

		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		if !reflect.DeepEqual(got, authorization.Grants{}) {
			t.Errorf("got %+v, want none", got)
		}
	})
}

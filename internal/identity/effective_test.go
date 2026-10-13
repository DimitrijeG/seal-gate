package identity_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

func TestEffectivePolicies(t *testing.T) {
	t.Run("an entity with no groups has its own policies", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		entity := identity.Entity{ID: hexID, Policies: []string{"dev"}}

		got, err := s.EffectivePolicies(t.Context(), entity)
		if err != nil {
			t.Fatalf("EffectivePolicies: %v", err)
		}

		if want := []string{"dev"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an entity's groups add their policies after its own", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[groupID] = identity.Group{ID: groupID, Policies: []string{"ops"}}
		entity := identity.Entity{ID: hexID, Policies: []string{"dev"}, Groups: []string{groupID}}

		got, err := s.EffectivePolicies(t.Context(), entity)
		if err != nil {
			t.Fatalf("EffectivePolicies: %v", err)
		}

		if want := []string{"dev", "ops"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a policy named twice appears once", func(t *testing.T) {
		tests := []struct {
			name   string
			entity identity.Entity
			groups []identity.Group
			want   []string
		}{
			{
				"own and group",
				identity.Entity{ID: hexID, Policies: []string{"dev"}, Groups: []string{groupID}},
				[]identity.Group{{ID: groupID, Policies: []string{"dev"}}},
				[]string{"dev"},
			},
			{
				"two groups",
				identity.Entity{ID: hexID, Groups: []string{hexID, groupID}},
				[]identity.Group{
					{ID: hexID, Policies: []string{"ops"}},
					{ID: groupID, Policies: []string{"ops"}},
				},
				[]string{"ops"},
			},
			{
				"own twice",
				identity.Entity{ID: hexID, Policies: []string{"dev", "dev"}},
				nil,
				[]string{"dev"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)
				for _, group := range tt.groups {
					groups.groups[group.ID] = group
				}

				got, err := s.EffectivePolicies(t.Context(), tt.entity)
				if err != nil {
					t.Fatalf("EffectivePolicies: %v", err)
				}

				if !slices.Equal(got, tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("an unreadable group is an error", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		// Skipping it instead could drop a deny and widen access.
		groups.groups[groupID] = identity.Group{ID: groupID, Policies: []string{"dev/ops"}}
		entity := identity.Entity{ID: hexID, Groups: []string{groupID}}

		_, err := s.EffectivePolicies(t.Context(), entity)

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("a missing group is skipped", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		entity := identity.Entity{ID: hexID, Policies: []string{"dev"}, Groups: []string{groupID}}

		got, err := s.EffectivePolicies(t.Context(), entity)
		if err != nil {
			t.Fatalf("EffectivePolicies: %v", err)
		}

		if want := []string{"dev"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an invalid group ID is refused", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		entity := identity.Entity{ID: hexID, Groups: []string{"../dev"}}

		_, err := s.EffectivePolicies(t.Context(), entity)

		if !errors.Is(err, identity.ErrInvalidGroupID) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidGroupID)
		}
	})

	t.Run("a repository failure reaches the caller", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
		}{
			{"sealed", identity.ErrSealed},
			{"unexpected", errors.New("disk failed")},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)
				groups.err = tt.err
				entity := identity.Entity{ID: hexID, Groups: []string{groupID}}

				_, err := s.EffectivePolicies(t.Context(), entity)

				if !errors.Is(err, tt.err) {
					t.Errorf("got %v, want %v", err, tt.err)
				}
			})
		}
	})
}

const groupID = "fedcba9876543210fedcba9876543210"

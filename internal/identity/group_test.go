package identity_test

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// fakeGroups keeps groups in a map; err, when set, fails every call.
type fakeGroups struct {
	groups map[string]identity.Group
	calls  int
	err    error
}

func (r *fakeGroups) Put(_ context.Context, group identity.Group) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.groups[group.ID] = group
	return nil
}

func (r *fakeGroups) Get(_ context.Context, id string) (identity.Group, error) {
	r.calls++
	if r.err != nil {
		return identity.Group{}, r.err
	}
	group, ok := r.groups[id]
	if !ok {
		return identity.Group{}, identity.ErrGroupNotFound
	}
	return group, nil
}

func (r *fakeGroups) Delete(_ context.Context, id string) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	delete(r.groups, id)
	return nil
}

func (r *fakeGroups) List(_ context.Context) ([]string, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return slices.Sorted(maps.Keys(r.groups)), nil
}

// racingGroups holds the first Get, after it has read, until a Delete has run
// or 100 ms pass, so an unguarded update writes after the delete.
type racingGroups struct {
	fakeGroups
	mu      sync.Mutex
	gets    atomic.Int32
	read    chan struct{}
	deleted chan struct{}
}

func newRacingGroups() *racingGroups {
	return &racingGroups{
		fakeGroups: fakeGroups{groups: make(map[string]identity.Group)},
		read:       make(chan struct{}),
		deleted:    make(chan struct{}),
	}
}

func (r *racingGroups) Put(ctx context.Context, group identity.Group) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeGroups.Put(ctx, group)
}

func (r *racingGroups) Get(ctx context.Context, id string) (identity.Group, error) {
	r.mu.Lock()
	group, err := r.fakeGroups.Get(ctx, id)
	r.mu.Unlock()

	if r.gets.Add(1) == 1 {
		close(r.read)
		select {
		case <-r.deleted:
		case <-time.After(100 * time.Millisecond):
		}
	}
	return group, err
}

func (r *racingGroups) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	err := r.fakeGroups.Delete(ctx, id)
	r.mu.Unlock()

	close(r.deleted)
	return err
}

// vanishingGroups lists gone as well as what it holds, as if gone were deleted between the List and its Get.
type vanishingGroups struct {
	fakeGroups
	gone string
}

func (r *vanishingGroups) List(ctx context.Context) ([]string, error) {
	ids, err := r.fakeGroups.List(ctx)
	return append(ids, r.gone), err
}

// racingGroupLists holds the first List, after it has read, until a second List has run or 100 ms pass,
// so two unguarded creates both scan before either writes.
type racingGroupLists struct {
	fakeGroups
	mu     sync.Mutex
	lists  atomic.Int32
	listed chan struct{}
	second chan struct{}
}

func newRacingGroupLists() *racingGroupLists {
	return &racingGroupLists{
		fakeGroups: fakeGroups{groups: make(map[string]identity.Group)},
		listed:     make(chan struct{}),
		second:     make(chan struct{}),
	}
}

func (r *racingGroupLists) Put(ctx context.Context, group identity.Group) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeGroups.Put(ctx, group)
}

func (r *racingGroupLists) Get(ctx context.Context, id string) (identity.Group, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeGroups.Get(ctx, id)
}

func (r *racingGroupLists) List(ctx context.Context) ([]string, error) {
	r.mu.Lock()
	ids, err := r.fakeGroups.List(ctx)
	r.mu.Unlock()

	switch r.lists.Add(1) {
	case 1:
		close(r.listed)
		select {
		case <-r.second:
		case <-time.After(100 * time.Millisecond):
		}
	case 2:
		close(r.second)
	}
	return ids, err
}

func newGroupService(t *testing.T) (*identity.GroupService, *fakeGroups, *fakeRandom) {
	t.Helper()
	s, groups, random, _ := newAuthorizedGroupService(t)
	return s, groups, random
}

func newAuthorizedGroupService(t *testing.T) (*identity.GroupService, *fakeGroups, *fakeRandom, *fakeAuthorizer) {
	t.Helper()
	groups := &fakeGroups{groups: make(map[string]identity.Group)}
	random := &fakeRandom{}
	authorizer := &fakeAuthorizer{}
	return identity.NewGroupService(groups, random, authorizer), groups, random, authorizer
}

func TestGroup(t *testing.T) {
	t.Run("every stored group is listed with its alias", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		other := strings.Repeat("01", 16)
		groups.groups[hexID] = identity.Group{ID: hexID, Alias: "ops", Policies: []string{"dev"}}
		groups.groups[other] = identity.Group{ID: other}
		want := []identity.GroupSummary{{ID: other}, {ID: hexID, Alias: "ops"}}

		got, err := s.ListGroups(t.Context(), principal)
		if err != nil {
			t.Fatalf("ListGroups: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an unreadable group fails the listing", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID, Policies: []string{"dev/ops"}}

		_, err := s.ListGroups(t.Context(), principal)

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("a stored key that is not a group ID fails the listing as unreadable", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups["not-an-id"] = identity.Group{ID: "not-an-id"}

		_, err := s.ListGroups(t.Context(), principal)

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("a group deleted while listed is left out", func(t *testing.T) {
		groups := &vanishingGroups{fakeGroups: fakeGroups{groups: make(map[string]identity.Group)}, gone: strings.Repeat("01", 16)}
		groups.groups[hexID] = identity.Group{ID: hexID}
		s := identity.NewGroupService(groups, &fakeRandom{}, &fakeAuthorizer{})
		want := []identity.GroupSummary{{ID: hexID}}

		got, err := s.ListGroups(t.Context(), principal)
		if err != nil {
			t.Fatalf("ListGroups: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a created group reads back with its policies", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		group := identity.Group{Policies: []string{"dev"}}

		id, err := s.CreateGroup(t.Context(), principal, group)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		got, err := s.GetGroup(t.Context(), principal, id)
		if err != nil {
			t.Fatalf("GetGroup: %v", err)
		}

		group.ID = id
		if !reflect.DeepEqual(got, group) {
			t.Errorf("got %+v, want %+v", got, group)
		}
	})

	t.Run("a created group keeps its alias", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		want := "ops"

		id, err := s.CreateGroup(t.Context(), principal, identity.Group{Alias: want})
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		got, err := s.GetGroup(t.Context(), principal, id)
		if err != nil {
			t.Fatalf("GetGroup: %v", err)
		}

		if got.Alias != want {
			t.Errorf("got %q, want %q", got.Alias, want)
		}
	})

	t.Run("a created group's ID is 16 random bytes in hex", func(t *testing.T) {
		s, _, _ := newGroupService(t)

		id, err := s.CreateGroup(t.Context(), principal, identity.Group{})
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}

		// fakeRandom's first call fills every byte with 1.
		if want := strings.Repeat("01", 16); id != want {
			t.Errorf("got %q, want %q", id, want)
		}
	})

	t.Run("an ID given to create is replaced", func(t *testing.T) {
		s, _, _ := newGroupService(t)

		id, err := s.CreateGroup(t.Context(), principal, identity.Group{ID: hexID})
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}

		if id == hexID {
			t.Errorf("got %q, want a generated ID", id)
		}
	})

	t.Run("a failed random source stores nothing", func(t *testing.T) {
		s, groups, random := newGroupService(t)
		randomErr := errors.New("entropy exhausted")
		random.err = randomErr

		_, err := s.CreateGroup(t.Context(), principal, identity.Group{})

		if !errors.Is(err, randomErr) {
			t.Errorf("err: got %v, want %v", err, randomErr)
		}
		if groups.calls != 0 {
			t.Errorf("calls: got %d, want 0", groups.calls)
		}
	})

	t.Run("reading a missing group is not found", func(t *testing.T) {
		s, _, _ := newGroupService(t)

		_, err := s.GetGroup(t.Context(), principal, hexID)

		if !errors.Is(err, identity.ErrGroupNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupNotFound)
		}
	})

	t.Run("a deleted group is not found", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		id, err := s.CreateGroup(t.Context(), principal, identity.Group{})
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}

		if err := s.DeleteGroup(t.Context(), principal, id); err != nil {
			t.Fatalf("DeleteGroup: %v", err)
		}

		_, err = s.GetGroup(t.Context(), principal, id)
		if !errors.Is(err, identity.ErrGroupNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupNotFound)
		}
	})

	t.Run("deleting a missing group is not an error", func(t *testing.T) {
		s, _, _ := newGroupService(t)

		if err := s.DeleteGroup(t.Context(), principal, hexID); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("an update replaces the policies", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		id, err := s.CreateGroup(t.Context(), principal, identity.Group{Policies: []string{"dev"}})
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		updated := identity.Group{ID: id, Policies: []string{"ops"}}

		if err := s.UpdateGroup(t.Context(), principal, updated); err != nil {
			t.Fatalf("UpdateGroup: %v", err)
		}

		got, err := s.GetGroup(t.Context(), principal, id)
		if err != nil {
			t.Fatalf("GetGroup: %v", err)
		}
		if !reflect.DeepEqual(got, updated) {
			t.Errorf("got %+v, want %+v", got, updated)
		}
	})

	t.Run("updating a missing group is not found", func(t *testing.T) {
		s, _, _ := newGroupService(t)

		err := s.UpdateGroup(t.Context(), principal, identity.Group{ID: hexID})

		if !errors.Is(err, identity.ErrGroupNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupNotFound)
		}
	})

	t.Run("updating a missing group does not create it", func(t *testing.T) {
		s, _, _ := newGroupService(t)
		_ = s.UpdateGroup(t.Context(), principal, identity.Group{ID: hexID}) // its error is the previous test's

		_, err := s.GetGroup(t.Context(), principal, hexID)

		if !errors.Is(err, identity.ErrGroupNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupNotFound)
		}
	})

	t.Run("an invalid group ID is refused", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
		}{
			{"empty", ""},
			{"31 characters", hexID[:31]},
			{"33 characters", hexID + "0"},
			{"uppercase", strings.ToUpper(hexID)},
			{"letter past f", "g" + hexID[1:]},
			{"path", "../" + hexID[3:]},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newGroupService(t)

				_, err := s.GetGroup(t.Context(), principal, tt.id)

				if !errors.Is(err, identity.ErrInvalidGroupID) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidGroupID)
				}
			})
		}
	})

	t.Run("a group with a valid ID reads back", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
		}{
			{"digits only", strings.Repeat("0123456789", 4)[:32]},
			{"letters only", strings.Repeat("abcdef", 6)[:32]},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)
				groups.groups[tt.id] = identity.Group{ID: tt.id}

				if _, err := s.GetGroup(t.Context(), principal, tt.id); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("every operation refuses an invalid group ID before the repository", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.GroupService) error
		}{
			{"get", func(ctx context.Context, s *identity.GroupService) error {
				_, err := s.GetGroup(ctx, principal, "../dev")
				return err
			}},
			{"update", func(ctx context.Context, s *identity.GroupService) error {
				return s.UpdateGroup(ctx, principal, identity.Group{ID: "../dev"})
			}},
			{"delete", func(ctx context.Context, s *identity.GroupService) error {
				return s.DeleteGroup(ctx, principal, "../dev")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, identity.ErrInvalidGroupID) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidGroupID)
				}
				if groups.calls != 0 {
					t.Errorf("calls: got %d, want 0", groups.calls)
				}
			})
		}
	})

	t.Run("an update with an invalid ID and policy name reports the ID", func(t *testing.T) {
		s, _, _ := newGroupService(t)

		err := s.UpdateGroup(t.Context(), principal, identity.Group{ID: "../dev", Policies: []string{"dev/ops"}})

		if !errors.Is(err, identity.ErrInvalidGroupID) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidGroupID)
		}
	})

	t.Run("an invalid policy name is refused", func(t *testing.T) {
		for _, tt := range invalidPolicyNames {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newGroupService(t)

				_, err := s.CreateGroup(t.Context(), principal, identity.Group{Policies: []string{tt.policy}})

				if !errors.Is(err, identity.ErrInvalidPolicyName) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidPolicyName)
				}
			})
		}
	})

	t.Run("a valid policy name is accepted", func(t *testing.T) {
		for _, tt := range validPolicyNames {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newGroupService(t)

				if _, err := s.CreateGroup(t.Context(), principal, identity.Group{Policies: []string{tt.policy}}); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("an invalid group alias is refused", func(t *testing.T) {
		tests := []struct {
			name  string
			alias string
		}{
			{"uppercase", "OPS"},
			{"too long", strings.Repeat("a", 129)},
			{"dot", "."},
			{"dot-dot", ".."},
			{"slash", "dev/ops"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newGroupService(t)

				_, err := s.CreateGroup(t.Context(), principal, identity.Group{Alias: tt.alias})

				if !errors.Is(err, identity.ErrInvalidAlias) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidAlias)
				}
			})
		}
	})

	t.Run("a group alias of the longest length is accepted", func(t *testing.T) {
		s, _, _ := newGroupService(t)

		_, err := s.CreateGroup(t.Context(), principal, identity.Group{Alias: strings.Repeat("a", 128)})

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("creating with an alias another group holds is refused", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID, Alias: "ops"}

		_, err := s.CreateGroup(t.Context(), principal, identity.Group{Alias: "ops"})

		if !errors.Is(err, identity.ErrGroupAliasTaken) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupAliasTaken)
		}
	})

	t.Run("updating to an alias another group holds is refused", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		other := strings.Repeat("01", 16)
		groups.groups[hexID] = identity.Group{ID: hexID, Alias: "ops"}
		groups.groups[other] = identity.Group{ID: other}

		err := s.UpdateGroup(t.Context(), principal, identity.Group{ID: other, Alias: "ops"})

		if !errors.Is(err, identity.ErrGroupAliasTaken) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupAliasTaken)
		}
	})

	t.Run("an update keeping the group's own alias is accepted", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID, Alias: "ops"}

		err := s.UpdateGroup(t.Context(), principal, identity.Group{ID: hexID, Alias: "ops", Policies: []string{"dev"}})

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("groups without an alias never clash", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID}

		_, err := s.CreateGroup(t.Context(), principal, identity.Group{})

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("an unreadable group refuses an alias rather than risk a duplicate", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID, Policies: []string{"dev/ops"}}

		_, err := s.CreateGroup(t.Context(), principal, identity.Group{Alias: "ops"})

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("a stored key that is not a group ID refuses an alias as unreadable", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups["not-an-id"] = identity.Group{ID: "not-an-id"}

		_, err := s.CreateGroup(t.Context(), principal, identity.Group{Alias: "ops"})

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("two creates racing for one group alias cannot both claim it", func(t *testing.T) {
		groups := newRacingGroupLists()
		s := identity.NewGroupService(groups, &fakeRandom{}, &fakeAuthorizer{})
		ctx := t.Context()

		errs := make([]error, 2)
		var wg sync.WaitGroup
		wg.Go(func() {
			_, errs[0] = s.CreateGroup(ctx, principal, identity.Group{Alias: "ops"})
		})
		// The second starts only once the first has scanned.
		<-groups.listed
		wg.Go(func() {
			_, errs[1] = s.CreateGroup(ctx, principal, identity.Group{Alias: "ops"})
		})
		wg.Wait()

		taken := 0
		for _, err := range errs {
			if errors.Is(err, identity.ErrGroupAliasTaken) {
				taken++
			} else if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}
		}
		if taken != 1 {
			t.Errorf("got %d refused, want 1", taken)
		}
	})

	t.Run("an invalid group alias never reaches the repository", func(t *testing.T) {
		bad := identity.Group{ID: hexID, Alias: "OPS"}

		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.GroupService) error
		}{
			{"create", func(ctx context.Context, s *identity.GroupService) error {
				_, err := s.CreateGroup(ctx, principal, bad)
				return err
			}},
			{"update", func(ctx context.Context, s *identity.GroupService) error {
				return s.UpdateGroup(ctx, principal, bad)
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, identity.ErrInvalidAlias) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidAlias)
				}
				if groups.calls != 0 {
					t.Errorf("calls: got %d, want 0", groups.calls)
				}
			})
		}
	})

	t.Run("an invalid policy name never reaches the repository", func(t *testing.T) {
		bad := identity.Group{ID: hexID, Policies: []string{"dev/ops"}}

		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.GroupService) error
		}{
			{"create", func(ctx context.Context, s *identity.GroupService) error {
				_, err := s.CreateGroup(ctx, principal, bad)
				return err
			}},
			{"update", func(ctx context.Context, s *identity.GroupService) error {
				return s.UpdateGroup(ctx, principal, bad)
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, identity.ErrInvalidPolicyName) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidPolicyName)
				}
				if groups.calls != 0 {
					t.Errorf("calls: got %d, want 0", groups.calls)
				}
			})
		}
	})

	t.Run("a group with no policies is accepted", func(t *testing.T) {
		tests := []struct {
			name  string
			group identity.Group
		}{
			{"nil", identity.Group{}},
			{"empty", identity.Group{Policies: []string{}}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newGroupService(t)

				if _, err := s.CreateGroup(t.Context(), principal, tt.group); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a stored group with an invalid policy name is unreadable", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		// Seeded past create, as a record from a faulty encoder would arrive.
		groups.groups[hexID] = identity.Group{ID: hexID, Policies: []string{"dev/ops"}}

		_, err := s.GetGroup(t.Context(), principal, hexID)

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("a stored group with an invalid alias is unreadable", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID, Alias: "OPS"}

		_, err := s.GetGroup(t.Context(), principal, hexID)

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("a stored group that fails validation cannot be updated", func(t *testing.T) {
		s, groups, _ := newGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID, Policies: []string{"dev/ops"}}

		err := s.UpdateGroup(t.Context(), principal, identity.Group{ID: hexID, Policies: []string{"ops"}})

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})

	t.Run("an update racing a delete cannot bring the group back", func(t *testing.T) {
		groups := newRacingGroups()
		groups.groups[hexID] = identity.Group{ID: hexID}
		s := identity.NewGroupService(groups, &fakeRandom{}, &fakeAuthorizer{})
		ctx := t.Context()

		var updateErr, deleteErr error
		var wg sync.WaitGroup
		wg.Go(func() {
			updateErr = s.UpdateGroup(ctx, principal, identity.Group{ID: hexID, Policies: []string{"ops"}})
		})
		// The delete starts only once the update has seen the group exist.
		<-groups.read
		wg.Go(func() { deleteErr = s.DeleteGroup(ctx, principal, hexID) })
		wg.Wait()

		if updateErr != nil {
			t.Fatalf("UpdateGroup: %v", updateErr)
		}
		if deleteErr != nil {
			t.Fatalf("DeleteGroup: %v", deleteErr)
		}
		_, err := s.GetGroup(ctx, principal, hexID)
		if !errors.Is(err, identity.ErrGroupNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupNotFound)
		}
	})

	t.Run("every group operation reports sealed", func(t *testing.T) {
		for _, op := range groupOperations {
			t.Run(op.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)
				groups.err = identity.ErrSealed

				err := op.call(t.Context(), s)

				if !errors.Is(err, identity.ErrSealed) {
					t.Errorf("got %v, want %v", err, identity.ErrSealed)
				}
			})
		}
	})

	t.Run("an unexpected group repository failure reaches the caller", func(t *testing.T) {
		for _, op := range groupOperations {
			t.Run(op.name, func(t *testing.T) {
				s, groups, _ := newGroupService(t)
				repoErr := errors.New("disk failed")
				groups.err = repoErr

				err := op.call(t.Context(), s)

				if !errors.Is(err, repoErr) {
					t.Errorf("got %v, want %v", err, repoErr)
				}
			})
		}
	})
}

// groupOperations calls each group method with valid input, so only the repository or the authorizer can fail it.
var groupOperations = []struct {
	name string
	call func(ctx context.Context, s *identity.GroupService) error
}{
	{"create", func(ctx context.Context, s *identity.GroupService) error {
		_, err := s.CreateGroup(ctx, principal, identity.Group{})
		return err
	}},
	{"get", func(ctx context.Context, s *identity.GroupService) error {
		_, err := s.GetGroup(ctx, principal, hexID)
		return err
	}},
	{"update", func(ctx context.Context, s *identity.GroupService) error {
		return s.UpdateGroup(ctx, principal, identity.Group{ID: hexID})
	}},
	{"delete", func(ctx context.Context, s *identity.GroupService) error {
		return s.DeleteGroup(ctx, principal, hexID)
	}},
	{"list", func(ctx context.Context, s *identity.GroupService) error {
		_, err := s.ListGroups(ctx, principal)
		return err
	}},
}

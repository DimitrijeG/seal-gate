package identity_test

import (
	"bytes"
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

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// fakeEntities keeps entities in a map; err, when set, fails every call.
type fakeEntities struct {
	entities map[string]identity.Entity
	calls    int
	err      error
}

func (r *fakeEntities) Put(_ context.Context, entity identity.Entity) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.entities[entity.ID] = entity
	return nil
}

func (r *fakeEntities) Get(_ context.Context, id string) (identity.Entity, error) {
	r.calls++
	if r.err != nil {
		return identity.Entity{}, r.err
	}
	entity, ok := r.entities[id]
	if !ok {
		return identity.Entity{}, identity.ErrEntityNotFound
	}
	return entity, nil
}

func (r *fakeEntities) Delete(_ context.Context, id string) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	delete(r.entities, id)
	return nil
}

func (r *fakeEntities) List(_ context.Context) ([]string, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return slices.Sorted(maps.Keys(r.entities)), nil
}

// racingEntities holds the first Get, after it has read, until a Delete has run
// or 100 ms pass, so an unguarded update writes after the delete.
type racingEntities struct {
	fakeEntities
	mu      sync.Mutex
	gets    atomic.Int32
	read    chan struct{}
	deleted chan struct{}
}

func newRacingEntities() *racingEntities {
	return &racingEntities{
		fakeEntities: fakeEntities{entities: make(map[string]identity.Entity)},
		read:         make(chan struct{}),
		deleted:      make(chan struct{}),
	}
}

func (r *racingEntities) Put(ctx context.Context, entity identity.Entity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeEntities.Put(ctx, entity)
}

func (r *racingEntities) Get(ctx context.Context, id string) (identity.Entity, error) {
	r.mu.Lock()
	entity, err := r.fakeEntities.Get(ctx, id)
	r.mu.Unlock()

	if r.gets.Add(1) == 1 {
		close(r.read)
		select {
		case <-r.deleted:
		case <-time.After(100 * time.Millisecond):
		}
	}
	return entity, err
}

func (r *racingEntities) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	err := r.fakeEntities.Delete(ctx, id)
	r.mu.Unlock()

	close(r.deleted)
	return err
}

// racingLists holds the first List, after it has read, until a second List has run or 100 ms pass,
// so two unguarded creates both scan before either writes.
type racingLists struct {
	fakeEntities
	mu     sync.Mutex
	lists  atomic.Int32
	listed chan struct{}
	second chan struct{}
}

func newRacingLists() *racingLists {
	return &racingLists{
		fakeEntities: fakeEntities{entities: make(map[string]identity.Entity)},
		listed:       make(chan struct{}),
		second:       make(chan struct{}),
	}
}

func (r *racingLists) Put(ctx context.Context, entity identity.Entity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeEntities.Put(ctx, entity)
}

func (r *racingLists) Get(ctx context.Context, id string) (identity.Entity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeEntities.Get(ctx, id)
}

func (r *racingLists) List(ctx context.Context) ([]string, error) {
	r.mu.Lock()
	ids, err := r.fakeEntities.List(ctx)
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

// fakeRandom fills each call's bytes with the call's number, starting at 1, and keeps the last slice it returned.
type fakeRandom struct {
	calls byte
	last  []byte
	err   error
}

func (r *fakeRandom) Bytes(n int) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.calls++
	r.last = bytes.Repeat([]byte{r.calls}, n)
	return r.last, nil
}

const (
	hexID = "0123456789abcdef0123456789abcdef"
	// callerID differs from hexID, so the caller is never the entity it acts on.
	callerID = "fedcba9876543210fedcba9876543210"
)

// principal is who every call acts as; these tests do not depend on who it is.
var principal = authorization.NewEntityPrincipal(callerID, "dev")

func newEntityService(t *testing.T) (*identity.EntityService, *fakeEntities, *fakeRandom) {
	t.Helper()
	s, entities, random, _ := newAuthorizedEntityService(t)
	return s, entities, random
}

func newAuthorizedEntityService(t *testing.T) (*identity.EntityService, *fakeEntities, *fakeRandom, *fakeAuthorizer) {
	t.Helper()
	entities := &fakeEntities{entities: make(map[string]identity.Entity)}
	random := &fakeRandom{}
	authorizer := &fakeAuthorizer{}
	return identity.NewEntityService(entities, random, authorizer), entities, random, authorizer
}

func TestEntity(t *testing.T) {
	t.Run("every stored entity's ID is listed", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		other := strings.Repeat("01", 16)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		entities.entities[other] = identity.Entity{ID: other}
		want := []string{other, hexID}

		got, err := s.ListEntities(t.Context(), principal)
		if err != nil {
			t.Fatalf("ListEntities: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a created entity reads back with its policies and groups", func(t *testing.T) {
		s, _, _ := newEntityService(t)
		entity := identity.Entity{Policies: []string{"dev"}, Groups: []string{hexID}}

		id, err := s.CreateEntity(t.Context(), principal, entity)
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}
		got, err := s.GetEntity(t.Context(), principal, id)
		if err != nil {
			t.Fatalf("GetEntity: %v", err)
		}

		entity.ID = id
		if !reflect.DeepEqual(got, entity) {
			t.Errorf("got %+v, want %+v", got, entity)
		}
	})

	t.Run("a created entity keeps its alias", func(t *testing.T) {
		s, _, _ := newEntityService(t)
		want := "ci-runner"

		id, err := s.CreateEntity(t.Context(), principal, identity.Entity{Alias: want})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}
		got, err := s.GetEntity(t.Context(), principal, id)
		if err != nil {
			t.Fatalf("GetEntity: %v", err)
		}

		if got.Alias != want {
			t.Errorf("got %q, want %q", got.Alias, want)
		}
	})

	t.Run("a created entity's ID is 16 random bytes in hex", func(t *testing.T) {
		s, _, _ := newEntityService(t)

		id, err := s.CreateEntity(t.Context(), principal, identity.Entity{})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}

		// fakeRandom's first call fills every byte with 1.
		if want := strings.Repeat("01", 16); id != want {
			t.Errorf("got %q, want %q", id, want)
		}
	})

	t.Run("an ID given to create is replaced", func(t *testing.T) {
		s, _, _ := newEntityService(t)

		id, err := s.CreateEntity(t.Context(), principal, identity.Entity{ID: hexID})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}

		if id == hexID {
			t.Errorf("got %q, want a generated ID", id)
		}
	})

	t.Run("a failed random source stores nothing", func(t *testing.T) {
		s, entities, random := newEntityService(t)
		randomErr := errors.New("entropy exhausted")
		random.err = randomErr

		_, err := s.CreateEntity(t.Context(), principal, identity.Entity{})

		if !errors.Is(err, randomErr) {
			t.Errorf("err: got %v, want %v", err, randomErr)
		}
		if entities.calls != 0 {
			t.Errorf("calls: got %d, want 0", entities.calls)
		}
	})

	t.Run("reading a missing entity is not found", func(t *testing.T) {
		s, _, _ := newEntityService(t)

		_, err := s.GetEntity(t.Context(), principal, hexID)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("a deleted entity is not found", func(t *testing.T) {
		s, _, _ := newEntityService(t)
		id, err := s.CreateEntity(t.Context(), principal, identity.Entity{})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}

		if err := s.DeleteEntity(t.Context(), principal, id); err != nil {
			t.Fatalf("DeleteEntity: %v", err)
		}

		_, err = s.GetEntity(t.Context(), principal, id)
		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("deleting a missing entity is not an error", func(t *testing.T) {
		s, _, _ := newEntityService(t)

		if err := s.DeleteEntity(t.Context(), principal, hexID); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("an update replaces the policies and groups", func(t *testing.T) {
		s, _, _ := newEntityService(t)
		id, err := s.CreateEntity(t.Context(), principal, identity.Entity{Policies: []string{"dev"}})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}
		updated := identity.Entity{ID: id, Policies: []string{"ops"}, Groups: []string{hexID}}

		if err := s.UpdateEntity(t.Context(), principal, updated); err != nil {
			t.Fatalf("UpdateEntity: %v", err)
		}

		got, err := s.GetEntity(t.Context(), principal, id)
		if err != nil {
			t.Fatalf("GetEntity: %v", err)
		}
		if !reflect.DeepEqual(got, updated) {
			t.Errorf("got %+v, want %+v", got, updated)
		}
	})

	t.Run("updating a missing entity is not found", func(t *testing.T) {
		s, _, _ := newEntityService(t)

		err := s.UpdateEntity(t.Context(), principal, identity.Entity{ID: hexID})

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("updating a missing entity does not create it", func(t *testing.T) {
		s, _, _ := newEntityService(t)
		_ = s.UpdateEntity(t.Context(), principal, identity.Entity{ID: hexID}) // its error is the previous test's

		_, err := s.GetEntity(t.Context(), principal, hexID)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("an invalid entity ID is refused", func(t *testing.T) {
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
				s, _, _ := newEntityService(t)

				_, err := s.GetEntity(t.Context(), principal, tt.id)

				if !errors.Is(err, identity.ErrInvalidEntityID) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidEntityID)
				}
			})
		}
	})

	t.Run("an entity with a valid ID reads back", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
		}{
			{"digits only", strings.Repeat("0123456789", 4)[:32]},
			{"letters only", strings.Repeat("abcdef", 6)[:32]},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _ := newEntityService(t)
				entities.entities[tt.id] = identity.Entity{ID: tt.id}

				if _, err := s.GetEntity(t.Context(), principal, tt.id); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("every operation refuses an invalid entity ID before the repository", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.EntityService) error
		}{
			{"get", func(ctx context.Context, s *identity.EntityService) error {
				_, err := s.GetEntity(ctx, principal, "../dev")
				return err
			}},
			{"update", func(ctx context.Context, s *identity.EntityService) error {
				return s.UpdateEntity(ctx, principal, identity.Entity{ID: "../dev"})
			}},
			{"delete", func(ctx context.Context, s *identity.EntityService) error {
				return s.DeleteEntity(ctx, principal, "../dev")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _ := newEntityService(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, identity.ErrInvalidEntityID) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidEntityID)
				}
				if entities.calls != 0 {
					t.Errorf("calls: got %d, want 0", entities.calls)
				}
			})
		}
	})

	t.Run("an invalid policy name is refused", func(t *testing.T) {
		for _, tt := range invalidPolicyNames {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newEntityService(t)

				_, err := s.CreateEntity(t.Context(), principal, identity.Entity{Policies: []string{tt.policy}})

				if !errors.Is(err, identity.ErrInvalidPolicyName) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidPolicyName)
				}
			})
		}
	})

	t.Run("a valid policy name is accepted", func(t *testing.T) {
		for _, tt := range validPolicyNames {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newEntityService(t)

				if _, err := s.CreateEntity(t.Context(), principal, identity.Entity{Policies: []string{tt.policy}}); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("an invalid group ID is refused", func(t *testing.T) {
		tests := []struct {
			name  string
			group string
		}{
			{"empty", ""},
			{"uppercase", strings.ToUpper(hexID)},
			{"policy name", "dev"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newEntityService(t)

				_, err := s.CreateEntity(t.Context(), principal, identity.Entity{Groups: []string{tt.group}})

				if !errors.Is(err, identity.ErrInvalidGroupID) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidGroupID)
				}
			})
		}
	})

	t.Run("an invalid alias is refused", func(t *testing.T) {
		tests := []struct {
			name  string
			alias string
		}{
			{"uppercase", "CI"},
			{"too long", strings.Repeat("a", 129)},
			{"dot", "."},
			{"dot-dot", ".."},
			{"slash", "ci/runner"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newEntityService(t)

				_, err := s.CreateEntity(t.Context(), principal, identity.Entity{Alias: tt.alias})

				if !errors.Is(err, identity.ErrInvalidAlias) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidAlias)
				}
			})
		}
	})

	t.Run("an alias of the longest length is accepted", func(t *testing.T) {
		s, _, _ := newEntityService(t)

		_, err := s.CreateEntity(t.Context(), principal, identity.Entity{Alias: strings.Repeat("a", 128)})

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("creating with an alias another entity holds is refused", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID, Alias: "ci"}

		_, err := s.CreateEntity(t.Context(), principal, identity.Entity{Alias: "ci"})

		if !errors.Is(err, identity.ErrAliasTaken) {
			t.Errorf("got %v, want %v", err, identity.ErrAliasTaken)
		}
	})

	t.Run("updating to an alias another entity holds is refused", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		other := strings.Repeat("01", 16)
		entities.entities[hexID] = identity.Entity{ID: hexID, Alias: "ci"}
		entities.entities[other] = identity.Entity{ID: other}

		err := s.UpdateEntity(t.Context(), principal, identity.Entity{ID: other, Alias: "ci"})

		if !errors.Is(err, identity.ErrAliasTaken) {
			t.Errorf("got %v, want %v", err, identity.ErrAliasTaken)
		}
	})

	t.Run("an update keeping the entity's own alias is accepted", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID, Alias: "ci"}

		err := s.UpdateEntity(t.Context(), principal, identity.Entity{ID: hexID, Alias: "ci", Policies: []string{"dev"}})

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("entities without an alias never clash", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}

		_, err := s.CreateEntity(t.Context(), principal, identity.Entity{})

		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("an unreadable entity refuses an alias rather than risk a duplicate", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID, Policies: []string{"dev/ops"}}

		_, err := s.CreateEntity(t.Context(), principal, identity.Entity{Alias: "ci"})

		if !errors.Is(err, identity.ErrUnreadableEntity) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
		}
	})

	t.Run("a stored key that is not an entity ID refuses an alias as unreadable", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		entities.entities["not-an-id"] = identity.Entity{ID: "not-an-id"}

		_, err := s.CreateEntity(t.Context(), principal, identity.Entity{Alias: "ci"})

		if !errors.Is(err, identity.ErrUnreadableEntity) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
		}
	})

	t.Run("two creates racing for one alias cannot both claim it", func(t *testing.T) {
		entities := newRacingLists()
		s := identity.NewEntityService(entities, &fakeRandom{}, &fakeAuthorizer{})
		ctx := t.Context()

		errs := make([]error, 2)
		var wg sync.WaitGroup
		wg.Go(func() {
			_, errs[0] = s.CreateEntity(ctx, principal, identity.Entity{Alias: "ci"})
		})
		// The second starts only once the first has scanned.
		<-entities.listed
		wg.Go(func() {
			_, errs[1] = s.CreateEntity(ctx, principal, identity.Entity{Alias: "ci"})
		})
		wg.Wait()

		taken := 0
		for _, err := range errs {
			if errors.Is(err, identity.ErrAliasTaken) {
				taken++
			} else if err != nil {
				t.Fatalf("CreateEntity: %v", err)
			}
		}
		if taken != 1 {
			t.Errorf("got %d refused, want 1", taken)
		}
	})

	t.Run("invalid lists never reach the repository", func(t *testing.T) {
		badPolicy := identity.Entity{ID: hexID, Policies: []string{"dev/ops"}}
		badGroup := identity.Entity{ID: hexID, Groups: []string{"dev"}}
		badAlias := identity.Entity{ID: hexID, Alias: "CI"}

		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.EntityService) error
			want error
		}{
			{"create, policy name", func(ctx context.Context, s *identity.EntityService) error {
				_, err := s.CreateEntity(ctx, principal, badPolicy)
				return err
			}, identity.ErrInvalidPolicyName},
			{"create, group ID", func(ctx context.Context, s *identity.EntityService) error {
				_, err := s.CreateEntity(ctx, principal, badGroup)
				return err
			}, identity.ErrInvalidGroupID},
			{"update, policy name", func(ctx context.Context, s *identity.EntityService) error {
				return s.UpdateEntity(ctx, principal, badPolicy)
			}, identity.ErrInvalidPolicyName},
			{"update, group ID", func(ctx context.Context, s *identity.EntityService) error {
				return s.UpdateEntity(ctx, principal, badGroup)
			}, identity.ErrInvalidGroupID},
			{"create, alias", func(ctx context.Context, s *identity.EntityService) error {
				_, err := s.CreateEntity(ctx, principal, badAlias)
				return err
			}, identity.ErrInvalidAlias},
			{"update, alias", func(ctx context.Context, s *identity.EntityService) error {
				return s.UpdateEntity(ctx, principal, badAlias)
			}, identity.ErrInvalidAlias},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _ := newEntityService(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, tt.want) {
					t.Errorf("err: got %v, want %v", err, tt.want)
				}
				if entities.calls != 0 {
					t.Errorf("calls: got %d, want 0", entities.calls)
				}
			})
		}
	})

	t.Run("an entity with no policies or groups is accepted", func(t *testing.T) {
		tests := []struct {
			name   string
			entity identity.Entity
		}{
			{"nil", identity.Entity{}},
			{"empty", identity.Entity{Policies: []string{}, Groups: []string{}}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newEntityService(t)

				if _, err := s.CreateEntity(t.Context(), principal, tt.entity); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a stored entity that fails validation is unreadable", func(t *testing.T) {
		tests := []struct {
			name   string
			entity identity.Entity
		}{
			{"policy name", identity.Entity{ID: hexID, Policies: []string{"dev/ops"}}},
			{"group ID", identity.Entity{ID: hexID, Groups: []string{"dev"}}},
			{"alias", identity.Entity{ID: hexID, Alias: "CI"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _ := newEntityService(t)
				// Seeded past create, as a record from a faulty encoder would arrive.
				entities.entities[hexID] = tt.entity

				_, err := s.GetEntity(t.Context(), principal, hexID)

				if !errors.Is(err, identity.ErrUnreadableEntity) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
				}
			})
		}
	})

	t.Run("a stored entity that fails validation cannot be updated", func(t *testing.T) {
		s, entities, _ := newEntityService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID, Policies: []string{"dev/ops"}}

		err := s.UpdateEntity(t.Context(), principal, identity.Entity{ID: hexID, Policies: []string{"ops"}})

		if !errors.Is(err, identity.ErrUnreadableEntity) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
		}
	})

	t.Run("an update racing a delete cannot bring the entity back", func(t *testing.T) {
		entities := newRacingEntities()
		entities.entities[hexID] = identity.Entity{ID: hexID}
		s := identity.NewEntityService(entities, &fakeRandom{}, &fakeAuthorizer{})
		ctx := t.Context()

		var updateErr, deleteErr error
		var wg sync.WaitGroup
		wg.Go(func() {
			updateErr = s.UpdateEntity(ctx, principal, identity.Entity{ID: hexID, Policies: []string{"ops"}})
		})
		// The delete starts only once the update has seen the entity exist.
		<-entities.read
		wg.Go(func() { deleteErr = s.DeleteEntity(ctx, principal, hexID) })
		wg.Wait()

		if updateErr != nil {
			t.Fatalf("UpdateEntity: %v", updateErr)
		}
		if deleteErr != nil {
			t.Fatalf("DeleteEntity: %v", deleteErr)
		}
		_, err := s.GetEntity(ctx, principal, hexID)
		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("every operation reports sealed", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, entities, _ := newEntityService(t)
				entities.err = identity.ErrSealed

				err := op.call(t.Context(), s)

				if !errors.Is(err, identity.ErrSealed) {
					t.Errorf("got %v, want %v", err, identity.ErrSealed)
				}
			})
		}
	})

	t.Run("an unexpected repository failure reaches the caller", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, entities, _ := newEntityService(t)
				repoErr := errors.New("disk failed")
				entities.err = repoErr

				err := op.call(t.Context(), s)

				if !errors.Is(err, repoErr) {
					t.Errorf("got %v, want %v", err, repoErr)
				}
			})
		}
	})
}

// invalidPolicyNames and validPolicyNames are shared by entities and groups, which hold names by the same rule.
var invalidPolicyNames = []struct {
	name   string
	policy string
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

var validPolicyNames = []struct {
	name   string
	policy string
}{
	{"every allowed character", "Az09._-"},
	{"leading dot", ".ops"},
	{"three dots", "..."},
	{"exactly 128 bytes", strings.Repeat("a", 128)},
}

// operations calls each service method with valid input, so only the repository or the authorizer can fail it.
var operations = []struct {
	name string
	call func(ctx context.Context, s *identity.EntityService) error
}{
	{"create", func(ctx context.Context, s *identity.EntityService) error {
		_, err := s.CreateEntity(ctx, principal, identity.Entity{})
		return err
	}},
	{"get", func(ctx context.Context, s *identity.EntityService) error {
		_, err := s.GetEntity(ctx, principal, hexID)
		return err
	}},
	{"update", func(ctx context.Context, s *identity.EntityService) error {
		return s.UpdateEntity(ctx, principal, identity.Entity{ID: hexID})
	}},
	{"delete", func(ctx context.Context, s *identity.EntityService) error {
		return s.DeleteEntity(ctx, principal, hexID)
	}},
	{"list", func(ctx context.Context, s *identity.EntityService) error {
		_, err := s.ListEntities(ctx, principal)
		return err
	}},
}

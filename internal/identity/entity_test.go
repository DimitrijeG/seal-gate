package identity_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// fakeRandom fills each call's bytes with the call's number, starting at 1.
type fakeRandom struct {
	calls byte
	err   error
}

func (r *fakeRandom) Bytes(n int) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.calls++
	return bytes.Repeat([]byte{r.calls}, n), nil
}

const hexID = "0123456789abcdef0123456789abcdef"

func newService(t *testing.T) (*identity.Service, *fakeEntities, *fakeRandom) {
	t.Helper()
	entities := &fakeEntities{entities: make(map[string]identity.Entity)}
	random := &fakeRandom{}
	return identity.New(entities, random), entities, random
}

func TestEntity(t *testing.T) {
	t.Run("a created entity reads back with its policies and groups", func(t *testing.T) {
		s, _, _ := newService(t)
		entity := identity.Entity{Policies: []string{"dev"}, Groups: []string{hexID}}

		id, err := s.CreateEntity(t.Context(), entity)
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}
		got, err := s.GetEntity(t.Context(), id)
		if err != nil {
			t.Fatalf("GetEntity: %v", err)
		}

		entity.ID = id
		if !reflect.DeepEqual(got, entity) {
			t.Errorf("got %+v, want %+v", got, entity)
		}
	})

	t.Run("a created entity's ID is 16 random bytes in hex", func(t *testing.T) {
		s, _, _ := newService(t)

		id, err := s.CreateEntity(t.Context(), identity.Entity{})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}

		// fakeRandom's first call fills every byte with 1.
		if want := strings.Repeat("01", 16); id != want {
			t.Errorf("got %q, want %q", id, want)
		}
	})

	t.Run("an ID given to create is replaced", func(t *testing.T) {
		s, _, _ := newService(t)

		id, err := s.CreateEntity(t.Context(), identity.Entity{ID: hexID})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}

		if id == hexID {
			t.Errorf("got %q, want a generated ID", id)
		}
	})

	t.Run("a failed random source stores nothing", func(t *testing.T) {
		s, entities, random := newService(t)
		randomErr := errors.New("entropy exhausted")
		random.err = randomErr

		_, err := s.CreateEntity(t.Context(), identity.Entity{})

		if !errors.Is(err, randomErr) {
			t.Errorf("err: got %v, want %v", err, randomErr)
		}
		if entities.calls != 0 {
			t.Errorf("calls: got %d, want 0", entities.calls)
		}
	})

	t.Run("reading a missing entity is not found", func(t *testing.T) {
		s, _, _ := newService(t)

		_, err := s.GetEntity(t.Context(), hexID)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("a deleted entity is not found", func(t *testing.T) {
		s, _, _ := newService(t)
		id, err := s.CreateEntity(t.Context(), identity.Entity{})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}

		if err := s.DeleteEntity(t.Context(), id); err != nil {
			t.Fatalf("DeleteEntity: %v", err)
		}

		_, err = s.GetEntity(t.Context(), id)
		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("deleting a missing entity is not an error", func(t *testing.T) {
		s, _, _ := newService(t)

		if err := s.DeleteEntity(t.Context(), hexID); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("an update replaces the policies and groups", func(t *testing.T) {
		s, _, _ := newService(t)
		id, err := s.CreateEntity(t.Context(), identity.Entity{Policies: []string{"dev"}})
		if err != nil {
			t.Fatalf("CreateEntity: %v", err)
		}
		updated := identity.Entity{ID: id, Policies: []string{"ops"}, Groups: []string{hexID}}

		if err := s.UpdateEntity(t.Context(), updated); err != nil {
			t.Fatalf("UpdateEntity: %v", err)
		}

		got, err := s.GetEntity(t.Context(), id)
		if err != nil {
			t.Fatalf("GetEntity: %v", err)
		}
		if !reflect.DeepEqual(got, updated) {
			t.Errorf("got %+v, want %+v", got, updated)
		}
	})

	t.Run("updating a missing entity is not found", func(t *testing.T) {
		s, _, _ := newService(t)

		err := s.UpdateEntity(t.Context(), identity.Entity{ID: hexID})

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("updating a missing entity does not create it", func(t *testing.T) {
		s, _, _ := newService(t)
		_ = s.UpdateEntity(t.Context(), identity.Entity{ID: hexID}) // its error is the previous test's

		_, err := s.GetEntity(t.Context(), hexID)

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
				s, _, _ := newService(t)

				_, err := s.GetEntity(t.Context(), tt.id)

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
				s, entities, _ := newService(t)
				entities.entities[tt.id] = identity.Entity{ID: tt.id}

				if _, err := s.GetEntity(t.Context(), tt.id); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("every operation refuses an invalid entity ID before the repository", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.Service) error
		}{
			{"get", func(ctx context.Context, s *identity.Service) error {
				_, err := s.GetEntity(ctx, "../dev")
				return err
			}},
			{"update", func(ctx context.Context, s *identity.Service) error {
				return s.UpdateEntity(ctx, identity.Entity{ID: "../dev"})
			}},
			{"delete", func(ctx context.Context, s *identity.Service) error {
				return s.DeleteEntity(ctx, "../dev")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _ := newService(t)

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
		tests := []struct {
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

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newService(t)

				_, err := s.CreateEntity(t.Context(), identity.Entity{Policies: []string{tt.policy}})

				if !errors.Is(err, identity.ErrInvalidPolicyName) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidPolicyName)
				}
			})
		}
	})

	t.Run("a valid policy name is accepted", func(t *testing.T) {
		tests := []struct {
			name   string
			policy string
		}{
			{"every allowed character", "Az09._-"},
			{"leading dot", ".ops"},
			{"three dots", "..."},
			{"exactly 128 bytes", strings.Repeat("a", 128)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _ := newService(t)

				if _, err := s.CreateEntity(t.Context(), identity.Entity{Policies: []string{tt.policy}}); err != nil {
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
				s, _, _ := newService(t)

				_, err := s.CreateEntity(t.Context(), identity.Entity{Groups: []string{tt.group}})

				if !errors.Is(err, identity.ErrInvalidGroupID) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidGroupID)
				}
			})
		}
	})

	t.Run("invalid lists never reach the repository", func(t *testing.T) {
		badPolicy := identity.Entity{ID: hexID, Policies: []string{"dev/ops"}}
		badGroup := identity.Entity{ID: hexID, Groups: []string{"dev"}}

		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.Service) error
			want error
		}{
			{"create, policy name", func(ctx context.Context, s *identity.Service) error {
				_, err := s.CreateEntity(ctx, badPolicy)
				return err
			}, identity.ErrInvalidPolicyName},
			{"create, group ID", func(ctx context.Context, s *identity.Service) error {
				_, err := s.CreateEntity(ctx, badGroup)
				return err
			}, identity.ErrInvalidGroupID},
			{"update, policy name", func(ctx context.Context, s *identity.Service) error {
				return s.UpdateEntity(ctx, badPolicy)
			}, identity.ErrInvalidPolicyName},
			{"update, group ID", func(ctx context.Context, s *identity.Service) error {
				return s.UpdateEntity(ctx, badGroup)
			}, identity.ErrInvalidGroupID},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _ := newService(t)

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
				s, _, _ := newService(t)

				if _, err := s.CreateEntity(t.Context(), tt.entity); err != nil {
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
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _ := newService(t)
				// Seeded past create, as a record from a faulty encoder would arrive.
				entities.entities[hexID] = tt.entity

				_, err := s.GetEntity(t.Context(), hexID)

				if !errors.Is(err, identity.ErrUnreadableEntity) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
				}
			})
		}
	})

	t.Run("an update racing a delete cannot bring the entity back", func(t *testing.T) {
		entities := newRacingEntities()
		entities.entities[hexID] = identity.Entity{ID: hexID}
		s := identity.New(entities, &fakeRandom{})
		ctx := t.Context()

		var updateErr, deleteErr error
		var wg sync.WaitGroup
		wg.Go(func() { updateErr = s.UpdateEntity(ctx, identity.Entity{ID: hexID, Policies: []string{"ops"}}) })
		// The delete starts only once the update has seen the entity exist.
		<-entities.read
		wg.Go(func() { deleteErr = s.DeleteEntity(ctx, hexID) })
		wg.Wait()

		if updateErr != nil {
			t.Fatalf("UpdateEntity: %v", updateErr)
		}
		if deleteErr != nil {
			t.Fatalf("DeleteEntity: %v", deleteErr)
		}
		_, err := s.GetEntity(ctx, hexID)
		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("every operation reports sealed", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, entities, _ := newService(t)
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
				s, entities, _ := newService(t)
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

// operations calls each service method with valid input, so only the repository can fail it.
var operations = []struct {
	name string
	call func(ctx context.Context, s *identity.Service) error
}{
	{"create", func(ctx context.Context, s *identity.Service) error {
		_, err := s.CreateEntity(ctx, identity.Entity{})
		return err
	}},
	{"get", func(ctx context.Context, s *identity.Service) error {
		_, err := s.GetEntity(ctx, hexID)
		return err
	}},
	{"update", func(ctx context.Context, s *identity.Service) error {
		return s.UpdateEntity(ctx, identity.Entity{ID: hexID})
	}},
	{"delete", func(ctx context.Context, s *identity.Service) error {
		return s.DeleteEntity(ctx, hexID)
	}},
}

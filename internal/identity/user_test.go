package identity_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// fakeUsers keeps users in a map; err, when set, fails every call.
type fakeUsers struct {
	users map[string]identity.StoredUser
	calls int
	err   error
}

func (r *fakeUsers) Put(_ context.Context, name string, user identity.StoredUser) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.users[name] = user
	return nil
}

func (r *fakeUsers) Delete(_ context.Context, name string) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	delete(r.users, name)
	return nil
}

// fakeHasher hashes to fakeHash, fast where argon2id is slow by design; err, when set, fails every call.
type fakeHasher struct {
	calls int
	err   error
}

func (h *fakeHasher) Hash(password []byte) (string, error) {
	h.calls++
	if h.err != nil {
		return "", h.err
	}
	return fakeHash(password), nil
}

// fakeHash is not the password, so a stored password shows as a mismatch.
func fakeHash(password []byte) string {
	return "hash:" + hex.EncodeToString(password)
}

var password = []byte("correct horse")

func newUserService(t *testing.T) (*identity.UserService, *fakeUsers, *fakeEntities, *fakeHasher) {
	t.Helper()
	s, users, entities, hasher, _ := newAuthorizedUserService(t)
	return s, users, entities, hasher
}

// newAuthorizedUserService stores an entity under hexID, so a set for it reaches the hasher.
func newAuthorizedUserService(t *testing.T) (*identity.UserService, *fakeUsers, *fakeEntities, *fakeHasher, *fakeAuthorizer) {
	t.Helper()
	users := &fakeUsers{users: make(map[string]identity.StoredUser)}
	entities := &fakeEntities{entities: map[string]identity.Entity{hexID: {ID: hexID}}}
	hasher := &fakeHasher{}
	authorizer := &fakeAuthorizer{}
	s := identity.NewUserService(users, hasher, identity.NewEntityService(entities, &fakeRandom{}, authorizer), authorizer)
	return s, users, entities, hasher, authorizer
}

func TestUser(t *testing.T) {
	t.Run("a set user is stored as its entity ID and the password's hash", func(t *testing.T) {
		s, users, _, _ := newUserService(t)
		want := identity.StoredUser{EntityID: hexID, PasswordHash: fakeHash(password)}

		if err := s.SetUser(t.Context(), principal, "alice", hexID, password); err != nil {
			t.Fatalf("SetUser: %v", err)
		}

		if got := users.users["alice"]; got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a failed hash reaches the caller and stores nothing", func(t *testing.T) {
		s, users, _, hasher := newUserService(t)
		hashErr := errors.New("out of memory")
		hasher.err = hashErr

		err := s.SetUser(t.Context(), principal, "alice", hexID, password)

		if !errors.Is(err, hashErr) {
			t.Errorf("err: got %v, want %v", err, hashErr)
		}
		if users.calls != 0 {
			t.Errorf("calls: got %d, want 0", users.calls)
		}
	})

	t.Run("an invalid username is refused before anything is called", func(t *testing.T) {
		tests := []struct {
			name     string
			username string
		}{
			{"empty", ""},
			{"uppercase", "Alice"},
			{"slash", "alice/bob"},
			{"dot", "."},
			{"dot-dot", ".."},
			{"space", "alice bob"},
			{"non-ASCII letter", "alicé"},
			{"over 128 bytes", strings.Repeat("a", 129)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, users, entities, hasher, authorizer := newAuthorizedUserService(t)

				err := s.SetUser(t.Context(), principal, tt.username, hexID, password)

				if !errors.Is(err, identity.ErrInvalidUsername) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidUsername)
				}
				if calls := users.calls + entities.calls + hasher.calls + authorizer.calls; calls != 0 {
					t.Errorf("calls: got %d, want 0", calls)
				}
			})
		}
	})

	t.Run("a valid username is accepted", func(t *testing.T) {
		tests := []struct {
			name     string
			username string
		}{
			{"every allowed character", "az09._-"},
			{"leading dot", ".alice"},
			{"three dots", "..."},
			{"exactly 128 bytes", strings.Repeat("a", 128)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _, _ := newUserService(t)

				if err := s.SetUser(t.Context(), principal, tt.username, hexID, password); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("an invalid password is refused before anything is called", func(t *testing.T) {
		tests := []struct {
			name     string
			password []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"over 1024 bytes", bytes.Repeat([]byte("a"), 1025)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, users, entities, hasher, authorizer := newAuthorizedUserService(t)

				err := s.SetUser(t.Context(), principal, "alice", hexID, tt.password)

				if !errors.Is(err, identity.ErrInvalidPassword) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidPassword)
				}
				if calls := users.calls + entities.calls + hasher.calls + authorizer.calls; calls != 0 {
					t.Errorf("calls: got %d, want 0", calls)
				}
			})
		}
	})

	t.Run("a password of 1024 bytes is accepted", func(t *testing.T) {
		s, _, _, _ := newUserService(t)

		if err := s.SetUser(t.Context(), principal, "alice", hexID, bytes.Repeat([]byte("a"), 1024)); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a user for a missing entity is refused", func(t *testing.T) {
		s, users, entities, _ := newUserService(t)
		delete(entities.entities, hexID)

		err := s.SetUser(t.Context(), principal, "alice", hexID, password)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("err: got %v, want %v", err, identity.ErrEntityNotFound)
		}
		if users.calls != 0 {
			t.Errorf("calls: got %d, want 0", users.calls)
		}
	})

	t.Run("a deleted user is gone", func(t *testing.T) {
		s, users, _, _ := newUserService(t)
		users.users["alice"] = identity.StoredUser{EntityID: hexID, PasswordHash: fakeHash(password)}

		if err := s.DeleteUser(t.Context(), principal, "alice"); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}

		if got, ok := users.users["alice"]; ok {
			t.Errorf("got %+v, want none", got)
		}
	})

	t.Run("delete refuses an invalid username before anything is called", func(t *testing.T) {
		s, users, _, _, authorizer := newAuthorizedUserService(t)

		err := s.DeleteUser(t.Context(), principal, "../alice")

		if !errors.Is(err, identity.ErrInvalidUsername) {
			t.Errorf("err: got %v, want %v", err, identity.ErrInvalidUsername)
		}
		if calls := users.calls + authorizer.calls; calls != 0 {
			t.Errorf("calls: got %d, want 0", calls)
		}
	})

	t.Run("every user operation reports sealed", func(t *testing.T) {
		for _, op := range userOperations {
			t.Run(op.name, func(t *testing.T) {
				s, users, _, _ := newUserService(t)
				users.err = identity.ErrSealed

				err := op.call(t.Context(), s)

				if !errors.Is(err, identity.ErrSealed) {
					t.Errorf("got %v, want %v", err, identity.ErrSealed)
				}
			})
		}
	})

	t.Run("an unexpected user repository failure reaches the caller", func(t *testing.T) {
		for _, op := range userOperations {
			t.Run(op.name, func(t *testing.T) {
				s, users, _, _ := newUserService(t)
				repoErr := errors.New("disk failed")
				users.err = repoErr

				err := op.call(t.Context(), s)

				if !errors.Is(err, repoErr) {
					t.Errorf("got %v, want %v", err, repoErr)
				}
			})
		}
	})
}

// userOperations calls each user method with valid input for alice and the entity under hexID,
// so only the repository, the hasher or the authorizer can fail it.
var userOperations = []struct {
	name string
	call func(ctx context.Context, s *identity.UserService) error
}{
	{"set", func(ctx context.Context, s *identity.UserService) error {
		return s.SetUser(ctx, principal, "alice", hexID, password)
	}},
	{"delete", func(ctx context.Context, s *identity.UserService) error {
		return s.DeleteUser(ctx, principal, "alice")
	}},
}

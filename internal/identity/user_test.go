package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
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

func (r *fakeUsers) Get(_ context.Context, name string) (identity.StoredUser, error) {
	r.calls++
	if r.err != nil {
		return identity.StoredUser{}, r.err
	}
	user, ok := r.users[name]
	if !ok {
		return identity.StoredUser{}, identity.ErrUserNotFound
	}
	return user, nil
}

func (r *fakeUsers) Delete(_ context.Context, name string) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	delete(r.users, name)
	return nil
}

func (r *fakeUsers) List(_ context.Context) ([]string, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return slices.Sorted(maps.Keys(r.users)), nil
}

// fakeHasher hashes to fakeHash, fast where argon2id is slow by design; err, when set, fails every call, and matchAll
// makes Verify match any hash. calls counts both methods; verifies counts Verify alone.
type fakeHasher struct {
	calls    int
	verifies int
	err      error
	matchAll bool
}

func (h *fakeHasher) Hash(password []byte) (string, error) {
	h.calls++
	if h.err != nil {
		return "", h.err
	}
	return fakeHash(password), nil
}

func (h *fakeHasher) Verify(password []byte, encoded string) (bool, error) {
	h.calls++
	h.verifies++
	if h.err != nil {
		return false, h.err
	}
	return h.matchAll || encoded == fakeHash(password), nil
}

// fakeHash is not the password, so a stored password shows as a mismatch.
func fakeHash(password []byte) string {
	return "hash:" + hex.EncodeToString(password)
}

var password = []byte("correct horse")

func newUserService(t *testing.T) (*identity.UserService, *fakeUsers, *fakeEntities, *fakeHasher) {
	t.Helper()
	s, f := newUserServiceFakes(t)
	return s, f.users, f.entities, f.hasher
}

func newAuthorizedUserService(t *testing.T) (*identity.UserService, *fakeUsers, *fakeEntities, *fakeHasher, *fakeAuthorizer) {
	t.Helper()
	s, f := newUserServiceFakes(t)
	return s, f.users, f.entities, f.hasher, f.authorizer
}

// userFakes are what a UserService calls; the entity and token services it is given run over them.
type userFakes struct {
	users      *fakeUsers
	entities   *fakeEntities
	hasher     *fakeHasher
	authorizer *fakeAuthorizer
	tokens     *fakeTokens
	clock      *fakeClock
}

// newUserServiceFakes stores an entity under hexID, so a set for it reaches the hasher.
func newUserServiceFakes(t *testing.T) (*identity.UserService, userFakes) {
	t.Helper()
	f := userFakes{
		users:      &fakeUsers{users: make(map[string]identity.StoredUser)},
		entities:   &fakeEntities{entities: map[string]identity.Entity{hexID: {ID: hexID}}},
		hasher:     &fakeHasher{},
		authorizer: &fakeAuthorizer{},
		tokens:     newFakeTokens(),
		clock:      newFakeClock(),
	}
	random := &fakeRandom{}
	entities := identity.NewEntityService(f.entities, random, f.authorizer)
	tokens := identity.NewTokenService(f.tokens, entities, fakeRoot{}, random, f.authorizer, f.clock, tokenLimits)
	s, err := identity.NewUserService(f.users, f.hasher, entities, tokens, f.authorizer)
	if err != nil {
		t.Fatalf("NewUserService: %v", err)
	}
	// The dummy hash at construction is not a call of the operation under test.
	f.hasher.calls = 0
	return s, f
}

// alice is a stored user of the entity under hexID whose password is password.
var alice = identity.StoredUser{EntityID: hexID, PasswordHash: fakeHash(password)}

func TestUser(t *testing.T) {
	t.Run("every stored user's name is listed", func(t *testing.T) {
		s, users, _, _ := newUserService(t)
		users.users["bob"] = alice
		users.users["alice"] = alice
		want := []string{"alice", "bob"}

		got, err := s.ListUsers(t.Context(), principal)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

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
	{"list", func(ctx context.Context, s *identity.UserService) error {
		_, err := s.ListUsers(ctx, principal)
		return err
	}},
}

func TestLogin(t *testing.T) {
	t.Run("the right password returns a token stored for the user's entity", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		f.users.users["alice"] = alice

		token, _, err := s.Login(t.Context(), "alice", password)
		if err != nil {
			t.Fatalf("Login: %v", err)
		}

		stored, ok := f.tokens.tokens[sha256.Sum256(token)]
		if !ok {
			t.Fatalf("got no stored token, want one")
		}
		if stored.EntityID != hexID {
			t.Errorf("got %q, want %q", stored.EntityID, hexID)
		}
	})

	t.Run("a login token expires one default TTL after it is issued", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		f.users.users["alice"] = alice
		f.clock.advance(time.Minute)
		want := f.clock.now.Add(tokenTTL)

		_, got, err := s.Login(t.Context(), "alice", password)
		if err != nil {
			t.Fatalf("Login: %v", err)
		}

		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a wrong password is refused", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		f.users.users["alice"] = alice

		_, _, err := s.Login(t.Context(), "alice", []byte("wrong horse"))

		if !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Errorf("err: got %v, want %v", err, identity.ErrInvalidCredentials)
		}
		if len(f.tokens.tokens) != 0 {
			t.Errorf("tokens: got %d, want 0", len(f.tokens.tokens))
		}
	})

	t.Run("an unknown user is refused the same way", func(t *testing.T) {
		s, _ := newUserServiceFakes(t)

		_, _, err := s.Login(t.Context(), "alice", password)

		if !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidCredentials)
		}
	})

	t.Run("an unknown user still verifies once", func(t *testing.T) {
		s, f := newUserServiceFakes(t)

		_, _, _ = s.Login(t.Context(), "alice", password)

		if f.hasher.verifies != 1 {
			t.Errorf("got %d, want 1", f.hasher.verifies)
		}
	})

	t.Run("an unknown user is refused even if the dummy hash matches", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		f.hasher.matchAll = true

		_, _, err := s.Login(t.Context(), "alice", password)

		if !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidCredentials)
		}
	})

	t.Run("a failed dummy hash fails construction", func(t *testing.T) {
		hashErr := errors.New("out of memory")
		hasher := &fakeHasher{err: hashErr}

		_, err := identity.NewUserService(&fakeUsers{}, hasher, nil, nil, &fakeAuthorizer{})

		if !errors.Is(err, hashErr) {
			t.Errorf("got %v, want %v", err, hashErr)
		}
	})

	t.Run("a user whose entity was deleted is refused the same way", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		f.users.users["alice"] = alice
		delete(f.entities.entities, hexID)

		_, _, err := s.Login(t.Context(), "alice", password)

		if !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Errorf("err: got %v, want %v", err, identity.ErrInvalidCredentials)
		}
		if len(f.tokens.tokens) != 0 {
			t.Errorf("tokens: got %d, want 0", len(f.tokens.tokens))
		}
	})

	t.Run("an invalid username is refused before anything is called", func(t *testing.T) {
		tests := []struct {
			name     string
			username string
		}{
			{"empty", ""},
			{"uppercase", "Alice"},
			{"over 128 bytes", strings.Repeat("a", 129)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, f := newUserServiceFakes(t)

				_, _, err := s.Login(t.Context(), tt.username, password)

				if !errors.Is(err, identity.ErrInvalidCredentials) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidCredentials)
				}
				if calls := f.users.calls + f.hasher.calls; calls != 0 {
					t.Errorf("calls: got %d, want 0", calls)
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
				s, f := newUserServiceFakes(t)
				f.users.users["alice"] = alice

				_, _, err := s.Login(t.Context(), "alice", tt.password)

				if !errors.Is(err, identity.ErrInvalidCredentials) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidCredentials)
				}
				if calls := f.users.calls + f.hasher.calls; calls != 0 {
					t.Errorf("calls: got %d, want 0", calls)
				}
			})
		}
	})

	t.Run("a corrupt user record is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			user identity.StoredUser
		}{
			{"invalid entity ID", identity.StoredUser{EntityID: "../dev", PasswordHash: fakeHash(password)}},
			{"empty hash", identity.StoredUser{EntityID: hexID}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, f := newUserServiceFakes(t)
				f.users.users["alice"] = tt.user

				_, _, err := s.Login(t.Context(), "alice", password)

				if !errors.Is(err, identity.ErrUnreadableUser) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableUser)
				}
			})
		}
	})

	t.Run("a stored hash that does not verify is unreadable", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		f.users.users["alice"] = alice
		f.hasher.err = errors.New("malformed hash")

		_, _, err := s.Login(t.Context(), "alice", password)

		if !errors.Is(err, identity.ErrUnreadableUser) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableUser)
		}
	})

	t.Run("login reports sealed", func(t *testing.T) {
		tests := []struct {
			name string
			seal func(f userFakes)
		}{
			{"user repository", func(f userFakes) { f.users.err = identity.ErrSealed }},
			{"token repository", func(f userFakes) { f.tokens.err = identity.ErrSealed }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, f := newUserServiceFakes(t)
				f.users.users["alice"] = alice
				tt.seal(f)

				_, _, err := s.Login(t.Context(), "alice", password)

				if !errors.Is(err, identity.ErrSealed) {
					t.Errorf("got %v, want %v", err, identity.ErrSealed)
				}
			})
		}
	})

	t.Run("an unexpected user repository failure reaches the caller", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		repoErr := errors.New("disk failed")
		f.users.err = repoErr

		_, _, err := s.Login(t.Context(), "alice", password)

		if !errors.Is(err, repoErr) {
			t.Errorf("got %v, want %v", err, repoErr)
		}
	})

	t.Run("login asks the authorizer nothing", func(t *testing.T) {
		s, f := newUserServiceFakes(t)
		f.users.users["alice"] = alice
		// No principal exists before login: the password is the proof.
		f.authorizer.err = authorization.ErrDenied

		if _, _, err := s.Login(t.Context(), "alice", password); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})
}

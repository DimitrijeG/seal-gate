package repository_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/repository"
)

// Any string does: the repository stores the hash it is given and never sees a password.
var aliceUser = identity.StoredUser{EntityID: entityID, PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$a2V5"}

func TestUserRepository(t *testing.T) {
	t.Run("a stored user reads back", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User

		if err := repo.Put(t.Context(), "alice", aliceUser); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), "alice")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if got != aliceUser {
			t.Errorf("got %+v, want %+v", got, aliceUser)
		}
	})

	t.Run("each user is one storage key under users/", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User
		want := []string{"users/alice"}

		if err := repo.Put(t.Context(), "alice", aliceUser); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := f.backend.List(t.Context(), "")
		if err != nil {
			t.Fatalf("backend List: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the stored record is version 1 JSON holding the entity ID and hash", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User
		// Decoded into any, so the field names are compared case-sensitively.
		var want any
		raw := `{"version": 1, "entity_id": "` + entityID + `", "password_hash": "` + aliceUser.PasswordHash + `"}`
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatalf("Unmarshal want: %v", err)
		}

		if err := repo.Put(t.Context(), "alice", aliceUser); err != nil {
			t.Fatalf("Put: %v", err)
		}
		data, err := f.encrypted.Get(t.Context(), "users/alice")
		if err != nil {
			t.Fatalf("barrier Get: %v", err)
		}
		var got any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("storage holds only ciphertext", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User
		plaintext := []byte(aliceUser.PasswordHash)

		if err := repo.Put(t.Context(), "alice", aliceUser); err != nil {
			t.Fatalf("Put: %v", err)
		}
		raw, err := f.backend.Get(t.Context(), "users/alice")
		if err != nil {
			t.Fatalf("backend Get: %v", err)
		}

		if bytes.Contains(raw, plaintext) {
			t.Error("stored value contains the plaintext")
		}
	})

	t.Run("reading a missing user is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User

		_, err := repo.Get(t.Context(), "alice")

		if !errors.Is(err, identity.ErrUserNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrUserNotFound)
		}
	})

	t.Run("a deleted user is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User

		if err := repo.Put(t.Context(), "alice", aliceUser); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := repo.Delete(t.Context(), "alice"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := repo.Get(t.Context(), "alice")

		if !errors.Is(err, identity.ErrUserNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrUserNotFound)
		}
	})

	t.Run("deleting a missing user is not an error", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User

		if err := repo.Delete(t.Context(), "alice"); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a stored record that does not decode is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			raw  string
		}{
			{"not JSON", "not json"},
			{"empty value", ""},
			{"a field of the wrong type", `{"version":1,"entity_id":1}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.User

				if err := f.encrypted.Put(t.Context(), "users/alice", []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), "alice")

				if !errors.Is(err, identity.ErrUnreadableUser) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableUser)
				}
			})
		}
	})

	t.Run("a stored record with an unknown version is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			raw  string
		}{
			{"version 2", `{"version":2,"entity_id":"` + entityID + `","password_hash":"x"}`},
			{"no version field", `{"entity_id":"` + entityID + `","password_hash":"x"}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.User

				if err := f.encrypted.Put(t.Context(), "users/alice", []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), "alice")

				if !errors.Is(err, identity.ErrUnreadableUser) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableUser)
				}
			})
		}
	})

	t.Run("every stored user's name is listed", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.User
		want := []string{"alice", "bob"}
		for _, name := range want {
			if err := repo.Put(t.Context(), name, aliceUser); err != nil {
				t.Fatalf("Put: %v", err)
			}
		}

		got, err := repo.List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("keys that are not users are not listed", func(t *testing.T) {
		f := newBarrierFixture(t)
		want := []string{"alice"}
		if err := f.set.User.Put(t.Context(), "alice", aliceUser); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := f.encrypted.Put(t.Context(), "entities/"+entityID, []byte("{}")); err != nil {
			t.Fatalf("barrier Put: %v", err)
		}

		got, err := f.set.User.List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("every operation is refused while sealed", func(t *testing.T) {
		tests := []struct {
			name string
			fn   func(*testing.T, *repository.Set) error
		}{
			{"put", func(t *testing.T, set *repository.Set) error {
				return set.User.Put(t.Context(), "alice", aliceUser)
			}},
			{"get", func(t *testing.T, set *repository.Set) error {
				_, err := set.User.Get(t.Context(), "alice")
				return err
			}},
			{"delete", func(t *testing.T, set *repository.Set) error {
				return set.User.Delete(t.Context(), "alice")
			}},
			{"list", func(t *testing.T, set *repository.Set) error {
				_, err := set.User.List(t.Context())
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				if err := f.set.User.Put(t.Context(), "alice", aliceUser); err != nil {
					t.Fatalf("Put: %v", err)
				}
				f.keys.Clear()

				err := tt.fn(t, f.set)

				if !errors.Is(err, identity.ErrSealed) {
					t.Errorf("got %v, want %v", err, identity.ErrSealed)
				}
			})
		}
	})
}

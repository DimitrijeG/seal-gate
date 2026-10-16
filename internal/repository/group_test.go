package repository_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/repository"
)

func devGroup() identity.Group {
	return identity.Group{
		ID:       groupID,
		Policies: []string{"dev", "ops"},
	}
}

func TestGroupRepository(t *testing.T) {
	t.Run("a stored group reads back", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group
		want := devGroup()

		if err := repo.Put(t.Context(), want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), groupID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("storage holds only ciphertext", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group
		// The record's field name is in every plaintext; a short policy name could occur in random bytes.
		plaintext := []byte("policies")

		if err := repo.Put(t.Context(), devGroup()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		keys, err := f.backend.List(t.Context(), "")
		if err != nil {
			t.Fatalf("backend List: %v", err)
		}
		if len(keys) == 0 {
			t.Fatal("backend holds no keys")
		}

		for _, key := range keys {
			raw, err := f.backend.Get(t.Context(), key)
			if err != nil {
				t.Fatalf("backend Get: %v", err)
			}

			if bytes.Contains(raw, plaintext) {
				t.Errorf("%s: stored value contains the plaintext", key)
			}
		}
	})

	t.Run("each group is one storage key under groups/", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group
		want := []string{"groups/" + groupID}

		if err := repo.Put(t.Context(), devGroup()); err != nil {
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

	t.Run("the stored record is version 1 JSON holding the policies", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group
		// Decoded into any, so the field names are compared case-sensitively.
		var want any
		if err := json.Unmarshal([]byte(`{"version": 1, "policies": ["dev", "ops"]}`), &want); err != nil {
			t.Fatalf("Unmarshal want: %v", err)
		}

		if err := repo.Put(t.Context(), devGroup()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		data, err := f.encrypted.Get(t.Context(), "groups/"+groupID)
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

	t.Run("a group with no policies reads back with none", func(t *testing.T) {
		tests := []struct {
			name     string
			policies []string
		}{
			{"nil", nil},
			{"empty", []string{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Group

				if err := repo.Put(t.Context(), identity.Group{ID: groupID, Policies: tt.policies}); err != nil {
					t.Fatalf("Put: %v", err)
				}
				got, err := repo.Get(t.Context(), groupID)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}

				if len(got.Policies) != 0 {
					t.Errorf("got %+v, want none", got)
				}
			})
		}
	})

	t.Run("reading a missing group is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group

		_, err := repo.Get(t.Context(), groupID)

		if !errors.Is(err, identity.ErrGroupNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupNotFound)
		}
	})

	t.Run("a deleted group is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group

		if err := repo.Put(t.Context(), devGroup()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := repo.Delete(t.Context(), groupID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := repo.Get(t.Context(), groupID)

		if !errors.Is(err, identity.ErrGroupNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrGroupNotFound)
		}
	})

	t.Run("deleting a missing group is not an error", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group

		if err := repo.Delete(t.Context(), groupID); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a tampered group is not reported as missing", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group
		key := "groups/" + groupID

		if err := repo.Put(t.Context(), devGroup()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		raw, err := f.backend.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("backend Get: %v", err)
		}
		tampered := bytes.Clone(raw)
		tampered[len(tampered)-1] ^= 1
		if err := f.backend.Put(t.Context(), key, tampered); err != nil {
			t.Fatalf("backend Put: %v", err)
		}
		_, err = repo.Get(t.Context(), groupID)

		if !errors.Is(err, cryptography.ErrDecryptionFailed) {
			t.Errorf("got %v, want %v", err, cryptography.ErrDecryptionFailed)
		}
	})

	t.Run("a stored record that does not decode is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			raw  string
		}{
			{"not JSON", "not json"},
			{"empty value", ""},
			{"a field of the wrong type", `{"version":1,"policies":"dev"}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Group

				if err := f.encrypted.Put(t.Context(), "groups/"+groupID, []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), groupID)

				if !errors.Is(err, identity.ErrUnreadableGroup) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
				}
			})
		}
	})

	t.Run("a stored record with an unknown version is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			raw  string
		}{
			{"version 2", `{"version":2,"policies":[]}`},
			{"no version field", `{"policies":[]}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Group

				if err := f.encrypted.Put(t.Context(), "groups/"+groupID, []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), groupID)

				if !errors.Is(err, identity.ErrUnreadableGroup) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
				}
			})
		}
	})

	t.Run("a stored group's alias reads back", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group
		want := "ops"

		if err := repo.Put(t.Context(), identity.Group{ID: groupID, Alias: want}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), groupID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if got.Alias != want {
			t.Errorf("got %q, want %q", got.Alias, want)
		}
	})

	t.Run("a version 1 record written without an alias reads back with none", func(t *testing.T) {
		f := newBarrierFixture(t)
		record := `{"version": 1, "policies": ["dev"]}`
		if err := f.encrypted.Put(t.Context(), "groups/"+groupID, []byte(record)); err != nil {
			t.Fatalf("barrier Put: %v", err)
		}

		got, err := f.set.Group.Get(t.Context(), groupID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if got.Alias != "" {
			t.Errorf("got %q, want none", got.Alias)
		}
	})

	t.Run("every stored group's ID is listed", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Group
		want := []string{entityID, groupID}
		for _, id := range want {
			if err := repo.Put(t.Context(), identity.Group{ID: id}); err != nil {
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

	t.Run("keys that are not groups are not listed", func(t *testing.T) {
		f := newBarrierFixture(t)
		want := []string{groupID}
		if err := f.set.Group.Put(t.Context(), devGroup()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := f.encrypted.Put(t.Context(), "entities/"+entityID, []byte("{}")); err != nil {
			t.Fatalf("barrier Put: %v", err)
		}

		got, err := f.set.Group.List(t.Context())
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
				return set.Group.Put(t.Context(), devGroup())
			}},
			{"get", func(t *testing.T, set *repository.Set) error {
				_, err := set.Group.Get(t.Context(), groupID)
				return err
			}},
			{"delete", func(t *testing.T, set *repository.Set) error {
				return set.Group.Delete(t.Context(), groupID)
			}},
			{"list", func(t *testing.T, set *repository.Set) error {
				_, err := set.Group.List(t.Context())
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				if err := f.set.Group.Put(t.Context(), devGroup()); err != nil {
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

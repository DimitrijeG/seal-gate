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

const (
	entityID = "00112233445566778899aabbccddeeff"
	groupID  = "ffeeddccbbaa99887766554433221100"
)

func devEntity() identity.Entity {
	return identity.Entity{
		ID:       entityID,
		Policies: []string{"dev", "ops"},
		Groups:   []string{groupID},
	}
}

func TestEntityRepository(t *testing.T) {
	t.Run("a stored entity reads back", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity
		want := devEntity()

		if err := repo.Put(t.Context(), want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), entityID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("storage holds only ciphertext", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity
		plaintext := []byte(groupID)

		if err := repo.Put(t.Context(), devEntity()); err != nil {
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

	t.Run("each entity is one storage key under entities/", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity
		want := []string{"entities/" + entityID}

		if err := repo.Put(t.Context(), devEntity()); err != nil {
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

	t.Run("the stored record is version 1 JSON holding the policies and groups", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity
		// Decoded into any, so the field names are compared case-sensitively.
		var want any
		if err := json.Unmarshal([]byte(`{"version": 1, "policies": ["dev", "ops"], "groups": ["`+groupID+`"]}`), &want); err != nil {
			t.Fatalf("Unmarshal want: %v", err)
		}

		if err := repo.Put(t.Context(), devEntity()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		data, err := f.encrypted.Get(t.Context(), "entities/"+entityID)
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

	t.Run("an entity with no policies or groups reads back with none", func(t *testing.T) {
		tests := []struct {
			name  string
			lists []string
		}{
			{"nil", nil},
			{"empty", []string{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Entity

				if err := repo.Put(t.Context(), identity.Entity{ID: entityID, Policies: tt.lists, Groups: tt.lists}); err != nil {
					t.Fatalf("Put: %v", err)
				}
				got, err := repo.Get(t.Context(), entityID)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}

				if len(got.Policies) != 0 || len(got.Groups) != 0 {
					t.Errorf("got %+v, want none", got)
				}
			})
		}
	})

	t.Run("reading a missing entity is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity

		_, err := repo.Get(t.Context(), entityID)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("a deleted entity is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity

		if err := repo.Put(t.Context(), devEntity()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := repo.Delete(t.Context(), entityID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := repo.Get(t.Context(), entityID)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("got %v, want %v", err, identity.ErrEntityNotFound)
		}
	})

	t.Run("deleting a missing entity is not an error", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity

		if err := repo.Delete(t.Context(), entityID); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a tampered entity is not reported as missing", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity
		key := "entities/" + entityID

		if err := repo.Put(t.Context(), devEntity()); err != nil {
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
		_, err = repo.Get(t.Context(), entityID)

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
				repo := f.set.Entity

				if err := f.encrypted.Put(t.Context(), "entities/"+entityID, []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), entityID)

				if !errors.Is(err, identity.ErrUnreadableEntity) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
				}
			})
		}
	})

	t.Run("a stored record with an unknown version is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			raw  string
		}{
			{"version 2", `{"version":2,"policies":[],"groups":[]}`},
			{"no version field", `{"policies":[],"groups":[]}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Entity

				if err := f.encrypted.Put(t.Context(), "entities/"+entityID, []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), entityID)

				if !errors.Is(err, identity.ErrUnreadableEntity) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
				}
			})
		}
	})

	t.Run("a stored entity's alias reads back", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity
		want := "ci-runner"

		if err := repo.Put(t.Context(), identity.Entity{ID: entityID, Alias: want}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), entityID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if got.Alias != want {
			t.Errorf("got %q, want %q", got.Alias, want)
		}
	})

	t.Run("a version 1 record written without an alias reads back with none", func(t *testing.T) {
		f := newBarrierFixture(t)
		record := `{"version": 1, "policies": ["dev"], "groups": []}`
		if err := f.encrypted.Put(t.Context(), "entities/"+entityID, []byte(record)); err != nil {
			t.Fatalf("barrier Put: %v", err)
		}

		got, err := f.set.Entity.Get(t.Context(), entityID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if got.Alias != "" {
			t.Errorf("got %q, want none", got.Alias)
		}
	})

	t.Run("every stored entity's ID is listed", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Entity
		want := []string{entityID, groupID}
		for _, id := range want {
			if err := repo.Put(t.Context(), identity.Entity{ID: id}); err != nil {
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

	t.Run("keys that are not entities are not listed", func(t *testing.T) {
		f := newBarrierFixture(t)
		want := []string{entityID}
		if err := f.set.Entity.Put(t.Context(), devEntity()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := f.encrypted.Put(t.Context(), "groups/"+groupID, []byte("{}")); err != nil {
			t.Fatalf("barrier Put: %v", err)
		}

		got, err := f.set.Entity.List(t.Context())
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
				return set.Entity.Put(t.Context(), devEntity())
			}},
			{"get", func(t *testing.T, set *repository.Set) error {
				_, err := set.Entity.Get(t.Context(), entityID)
				return err
			}},
			{"delete", func(t *testing.T, set *repository.Set) error {
				return set.Entity.Delete(t.Context(), entityID)
			}},
			{"list", func(t *testing.T, set *repository.Set) error {
				_, err := set.Entity.List(t.Context())
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				if err := f.set.Entity.Put(t.Context(), devEntity()); err != nil {
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

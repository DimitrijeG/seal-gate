package repository_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/repository"
)

func devPolicy() authorization.Policy {
	return authorization.Policy{
		Name: "dev",
		Rules: []authorization.Rule{{
			Path:         "secrets/dev/*",
			Capabilities: []authorization.Capability{authorization.CapabilityRead, authorization.CapabilityList},
		}},
	}
}

func TestPolicyRepository(t *testing.T) {
	t.Run("a stored policy reads back", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy
		want := devPolicy()

		if err := repo.Put(t.Context(), want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), "dev")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("storage holds only ciphertext", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy
		plaintext := []byte("secrets/dev/*")

		if err := repo.Put(t.Context(), devPolicy()); err != nil {
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

	t.Run("each policy is one storage key under policies/", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy
		want := []string{"policies/dev"}

		if err := repo.Put(t.Context(), devPolicy()); err != nil {
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

	t.Run("the stored record is version 1 JSON holding the rules", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy
		// Decoded into any, so the field names are compared case-sensitively.
		var want any
		if err := json.Unmarshal([]byte(`{"version": 1, "rules": [{"path": "secrets/dev/*", "capabilities": ["read", "list"]}]}`), &want); err != nil {
			t.Fatalf("Unmarshal want: %v", err)
		}

		if err := repo.Put(t.Context(), devPolicy()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		data, err := f.encrypted.Get(t.Context(), "policies/dev")
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

	t.Run("a policy with no rules reads back with none", func(t *testing.T) {
		tests := []struct {
			name  string
			rules []authorization.Rule
		}{
			{"nil", nil},
			{"empty", []authorization.Rule{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Policy

				if err := repo.Put(t.Context(), authorization.Policy{Name: "dev", Rules: tt.rules}); err != nil {
					t.Fatalf("Put: %v", err)
				}
				got, err := repo.Get(t.Context(), "dev")
				if err != nil {
					t.Fatalf("Get: %v", err)
				}

				if len(got.Rules) != 0 {
					t.Errorf("got %+v, want none", got.Rules)
				}
			})
		}
	})

	t.Run("reading a missing policy is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy

		_, err := repo.Get(t.Context(), "missing")

		if !errors.Is(err, authorization.ErrNotFound) {
			t.Errorf("got %v, want %v", err, authorization.ErrNotFound)
		}
	})

	t.Run("a deleted policy is not found", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy

		if err := repo.Put(t.Context(), devPolicy()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := repo.Delete(t.Context(), "dev"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := repo.Get(t.Context(), "dev")

		if !errors.Is(err, authorization.ErrNotFound) {
			t.Errorf("got %v, want %v", err, authorization.ErrNotFound)
		}
	})

	t.Run("deleting a missing policy is not an error", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy

		if err := repo.Delete(t.Context(), "missing"); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a tampered policy is not reported as missing", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Policy
		key := "policies/dev"

		if err := repo.Put(t.Context(), devPolicy()); err != nil {
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
		_, err = repo.Get(t.Context(), "dev")

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
			{"a field of the wrong type", `{"version":"one"}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Policy

				if err := f.encrypted.Put(t.Context(), "policies/dev", []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), "dev")

				if !errors.Is(err, authorization.ErrUnreadablePolicy) {
					t.Errorf("got %v, want %v", err, authorization.ErrUnreadablePolicy)
				}
			})
		}
	})

	t.Run("a stored record with an unknown version is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			raw  string
		}{
			{"version 2", `{"version":2,"rules":[]}`},
			{"no version field", `{"rules":[]}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Policy

				if err := f.encrypted.Put(t.Context(), "policies/dev", []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), "dev")

				if !errors.Is(err, authorization.ErrUnreadablePolicy) {
					t.Errorf("got %v, want %v", err, authorization.ErrUnreadablePolicy)
				}
			})
		}
	})

	t.Run("every operation is refused while sealed", func(t *testing.T) {
		tests := []struct {
			name string
			fn   func(*testing.T, *repository.Set) error
		}{
			{"put", func(t *testing.T, set *repository.Set) error {
				return set.Policy.Put(t.Context(), devPolicy())
			}},
			{"get", func(t *testing.T, set *repository.Set) error {
				_, err := set.Policy.Get(t.Context(), "dev")
				return err
			}},
			{"delete", func(t *testing.T, set *repository.Set) error {
				return set.Policy.Delete(t.Context(), "dev")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				if err := f.set.Policy.Put(t.Context(), devPolicy()); err != nil {
					t.Fatalf("Put: %v", err)
				}
				f.keys.Clear()

				err := tt.fn(t, f.set)

				if !errors.Is(err, authorization.ErrSealed) {
					t.Errorf("got %v, want %v", err, authorization.ErrSealed)
				}
			})
		}
	})
}

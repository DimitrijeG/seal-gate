package repository_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/repository"
)

var (
	// Any 32 bytes do: the repository is given a hash and never sees a token.
	tokenHash   = sha256.Sum256([]byte("token"))
	tokenKey    = "tokens/" + hex.EncodeToString(tokenHash[:])
	tokenExpiry = time.Date(2026, 10, 1, 13, 30, 0, 0, time.UTC)
)

func TestTokenRepository(t *testing.T) {
	t.Run("a stored token reads back as its entity ID", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Token

		if err := repo.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), tokenHash)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if got.EntityID != entityID {
			t.Errorf("got %q, want %q", got.EntityID, entityID)
		}
	})

	t.Run("a stored token's expiry reads back", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Token

		if err := repo.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID, ExpiresAt: tokenExpiry}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), tokenHash)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !got.ExpiresAt.Equal(tokenExpiry) {
			t.Errorf("got %v, want %v", got.ExpiresAt, tokenExpiry)
		}
	})

	t.Run("storage holds only ciphertext", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Token
		plaintext := []byte(entityID)

		if err := repo.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID}); err != nil {
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

	t.Run("each token is one storage key, its hash in hex under tokens/", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Token
		want := []string{tokenKey}

		if err := repo.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID}); err != nil {
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

	t.Run("the stored record is version 2 JSON holding the entity ID and its expiry", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Token
		// Decoded into any, so the field names are compared case-sensitively.
		var want any
		if err := json.Unmarshal([]byte(`{"version": 2, "entity_id": "`+entityID+`", "expires_at": "2026-10-01T13:30:00Z"}`), &want); err != nil {
			t.Fatalf("Unmarshal want: %v", err)
		}

		if err := repo.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID, ExpiresAt: tokenExpiry}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		data, err := f.encrypted.Get(t.Context(), tokenKey)
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

	t.Run("reading a missing token is an invalid token", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Token

		_, err := repo.Get(t.Context(), tokenHash)

		if !errors.Is(err, identity.ErrInvalidToken) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidToken)
		}
	})

	t.Run("a tampered token is not reported as missing", func(t *testing.T) {
		f := newBarrierFixture(t)
		repo := f.set.Token

		if err := repo.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		raw, err := f.backend.Get(t.Context(), tokenKey)
		if err != nil {
			t.Fatalf("backend Get: %v", err)
		}
		tampered := bytes.Clone(raw)
		tampered[len(tampered)-1] ^= 1
		if err := f.backend.Put(t.Context(), tokenKey, tampered); err != nil {
			t.Fatalf("backend Put: %v", err)
		}
		_, err = repo.Get(t.Context(), tokenHash)

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
			{"a field of the wrong type", `{"version":1,"entity_id":1}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Token

				if err := f.encrypted.Put(t.Context(), tokenKey, []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), tokenHash)

				if !errors.Is(err, identity.ErrUnreadableToken) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableToken)
				}
			})
		}
	})

	t.Run("a stored record with an unknown version is unreadable", func(t *testing.T) {
		tests := []struct {
			name string
			raw  string
		}{
			{"version 1", `{"version":1,"entity_id":"` + entityID + `"}`},
			{"version 3", `{"version":3,"entity_id":"` + entityID + `","expires_at":"2026-10-01T13:30:00Z"}`},
			{"no version field", `{"entity_id":"` + entityID + `"}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				repo := f.set.Token

				if err := f.encrypted.Put(t.Context(), tokenKey, []byte(tt.raw)); err != nil {
					t.Fatalf("barrier Put: %v", err)
				}
				_, err := repo.Get(t.Context(), tokenHash)

				if !errors.Is(err, identity.ErrUnreadableToken) {
					t.Errorf("got %v, want %v", err, identity.ErrUnreadableToken)
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
				return set.Token.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID})
			}},
			{"get", func(t *testing.T, set *repository.Set) error {
				_, err := set.Token.Get(t.Context(), tokenHash)
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBarrierFixture(t)
				if err := f.set.Token.Put(t.Context(), tokenHash, identity.StoredToken{EntityID: entityID}); err != nil {
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

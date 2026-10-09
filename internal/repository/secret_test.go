package repository_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/repository"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

// storedSecret decodes the stored layout without the repository's own type.
type storedSecret struct {
	Version int    `json:"version"`
	Value   []byte `json:"value"`
}

// secretsFixture holds the repository with the raw backend and the barrier beneath it.
type secretsFixture struct {
	set       *repository.Set
	backend   storage.Backend
	encrypted *barrier.AEADBarrier
	keys      *cryptography.KeyHolder
}

func newSecrets(t *testing.T) secretsFixture {
	t.Helper()

	key, err := cryptography.CryptoRandom{}.Bytes(32)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	keys := cryptography.NewKeyHolder()
	if err := keys.Install(key); err != nil {
		t.Fatalf("Install: %v", err)
	}

	cipher, err := cryptography.NewAEADCipher("aes-256-gcm")
	if err != nil {
		t.Fatalf("NewAEADCipher: %v", err)
	}

	backend := memory.New()
	encrypted := barrier.NewAEADBarrier(backend, keys, cipher)
	return secretsFixture{
		set:       repository.NewSet(backend, encrypted),
		backend:   backend,
		encrypted: encrypted,
		keys:      keys,
	}
}

func TestSecretRepository(t *testing.T) {
	t.Run("a stored secret reads back", func(t *testing.T) {
		f := newSecrets(t)
		repo := f.set.Secret
		want := []byte("secret")

		if err := repo.Put(t.Context(), "db/password", want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := repo.Get(t.Context(), "db/password")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("storage holds only ciphertext", func(t *testing.T) {
		f := newSecrets(t)
		repo := f.set.Secret
		plaintext := []byte("very secret value")

		if err := repo.Put(t.Context(), "db/password", plaintext); err != nil {
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

	t.Run("each path is one storage key under secrets/", func(t *testing.T) {
		tests := []struct {
			name, path string
			want       []string
		}{
			{"flat path", "api-key", []string{"secrets/api-key"}},
			{"nested path", "db/password", []string{"secrets/db/password"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newSecrets(t)
				repo := f.set.Secret
				value := []byte("secret")

				if err := repo.Put(t.Context(), tt.path, value); err != nil {
					t.Fatalf("Put: %v", err)
				}
				keys, err := f.backend.List(t.Context(), "")
				if err != nil {
					t.Fatalf("backend List: %v", err)
				}

				if !slices.Equal(keys, tt.want) {
					t.Errorf("got %v, want %v", keys, tt.want)
				}
			})
		}
	})

	t.Run("the stored record is version 1 JSON holding the value", func(t *testing.T) {
		f := newSecrets(t)
		repo := f.set.Secret
		value := []byte("very secret value")

		if err := repo.Put(t.Context(), "db/password", value); err != nil {
			t.Fatalf("Put: %v", err)
		}
		data, err := f.encrypted.Get(t.Context(), "secrets/db/password")
		if err != nil {
			t.Fatalf("barrier Get: %v", err)
		}
		var record storedSecret
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}

		if record.Version != 1 {
			t.Errorf("Version: got %d, want 1", record.Version)
		}
		if !bytes.Equal(record.Value, value) {
			t.Errorf("Value: got %q, want %q", record.Value, value)
		}
	})

	t.Run("a secret at a sys/ path leaves the system record intact", func(t *testing.T) {
		f := newSecrets(t)
		want := newSystemState()
		repo := f.set.Secret
		value := []byte("overwrite")

		mustSave(t, f.set.System, want)
		if err := repo.Put(t.Context(), "sys/initialization", value); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got := mustLoad(t, f.set.System)

		assertStateEqual(t, got, want)
	})

	t.Run("an empty secret reads back empty", func(t *testing.T) {
		tests := []struct {
			name  string
			value []byte
		}{
			{"nil value", nil},
			{"empty value", []byte{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newSecrets(t)
				repo := f.set.Secret

				if err := repo.Put(t.Context(), "db/password", tt.value); err != nil {
					t.Fatalf("Put: %v", err)
				}
				got, err := repo.Get(t.Context(), "db/password")
				if err != nil {
					t.Fatalf("Get: %v", err)
				}

				if len(got) != 0 {
					t.Errorf("got %q, want empty", got)
				}
			})
		}
	})

	t.Run("reading a missing secret is not found", func(t *testing.T) {
		f := newSecrets(t)
		repo := f.set.Secret

		_, err := repo.Get(t.Context(), "missing")

		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("a deleted secret is not found", func(t *testing.T) {
		f := newSecrets(t)
		repo := f.set.Secret
		value := []byte("secret")

		if err := repo.Put(t.Context(), "db/password", value); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := repo.Delete(t.Context(), "db/password"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := repo.Get(t.Context(), "db/password")

		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("listing returns the paths under a prefix, without the storage prefix", func(t *testing.T) {
		tests := []struct {
			name, prefix string
			want         []string
		}{
			{"every secret", "", []string{"api-key", "db/password", "db/user"}},
			{"nested prefix", "db/", []string{"db/password", "db/user"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newSecrets(t)
				repo := f.set.Secret
				value := []byte("secret")

				// The system record must not show up as a secret.
				mustSave(t, f.set.System, newSystemState())
				for _, path := range []string{"api-key", "db/password", "db/user"} {
					if err := repo.Put(t.Context(), path, value); err != nil {
						t.Fatalf("Put: %v", err)
					}
				}
				got, err := repo.List(t.Context(), tt.prefix)
				if err != nil {
					t.Fatalf("List: %v", err)
				}

				if !slices.Equal(got, tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("every operation is refused while sealed", func(t *testing.T) {
		value := []byte("secret")
		tests := []struct {
			name string
			fn   func(*testing.T, *repository.Set) error
		}{
			{"put", func(t *testing.T, set *repository.Set) error {
				return set.Secret.Put(t.Context(), "db/password", value)
			}},
			{"get", func(t *testing.T, set *repository.Set) error {
				_, err := set.Secret.Get(t.Context(), "db/password")
				return err
			}},
			{"delete", func(t *testing.T, set *repository.Set) error {
				return set.Secret.Delete(t.Context(), "db/password")
			}},
			{"list", func(t *testing.T, set *repository.Set) error {
				_, err := set.Secret.List(t.Context(), "")
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newSecrets(t)
				if err := f.set.Secret.Put(t.Context(), "db/password", value); err != nil {
					t.Fatalf("Put: %v", err)
				}
				f.keys.Clear()

				err := tt.fn(t, f.set)

				if !errors.Is(err, barrier.ErrSealed) {
					t.Errorf("got %v, want %v", err, barrier.ErrSealed)
				}
			})
		}
	})
}

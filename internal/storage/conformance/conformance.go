// Package conformance defines what a working storage backend is: every backend runs its suite.
package conformance

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

// Run tests a backend against the storage contract;
// open is called once per case and must return an empty backend.
func Run(t *testing.T, open func(t *testing.T) storage.Backend) {
	t.Run("getting a key that was never put returns ErrNotFound", func(t *testing.T) {
		key := "non-existent"
		b := open(t)

		_, err := b.Get(t.Context(), key)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("a value put under a key reads back", func(t *testing.T) {
		tests := []struct {
			name  string
			value []byte
		}{
			{"nil value", nil},
			{"empty value", []byte{}},
			{"non-empty value", []byte("value")},
		}

		key := "key"
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				b := open(t)
				mustPut(t, b, key, tt.value)

				got := mustGet(t, b, key)
				if !bytes.Equal(got, tt.value) {
					t.Errorf("got %x, want %x", got, tt.value)
				}
			})
		}
	})

	t.Run("putting a key again replaces its value", func(t *testing.T) {
		b := open(t)
		key := "key"
		value1 := []byte("first")
		value2 := []byte("second")

		mustPut(t, b, key, value1)
		mustPut(t, b, key, value2)

		got := mustGet(t, b, key)
		if !bytes.Equal(got, value2) {
			t.Errorf("got %x, want %x", got, value2)
		}
	})

	t.Run("values under different keys do not overwrite each other", func(t *testing.T) {
		b := open(t)
		key1, key2 := "key1", "key2"
		value1, value2 := []byte("first"), []byte("second")

		mustPut(t, b, key1, value1)
		mustPut(t, b, key2, value2)

		got1 := mustGet(t, b, key1)
		got2 := mustGet(t, b, key2)

		if !bytes.Equal(got1, value1) {
			t.Errorf("got %x, want %x", got1, value1)
		}
		if !bytes.Equal(got2, value2) {
			t.Errorf("got %x, want %x", got2, value2)
		}
	})

	t.Run("changing the caller's slice after put does not change the stored value", func(t *testing.T) {
		b := open(t)
		key := "key"
		value := []byte("value")
		want := bytes.Clone(value)

		mustPut(t, b, key, value)
		clear(value)

		got := mustGet(t, b, key)
		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("changing the slice returned by get does not change the stored value", func(t *testing.T) {
		b := open(t)
		key := "key"
		value := []byte("value")

		mustPut(t, b, key, value)
		got1 := mustGet(t, b, key)
		clear(got1)
		got2 := mustGet(t, b, key)

		if !bytes.Equal(got2, value) {
			t.Errorf("got %x, want %x", got2, value)
		}
	})

	t.Run("a deleted key reads as ErrNotFound", func(t *testing.T) {
		b := open(t)
		key := "key"

		mustPut(t, b, key, []byte("value"))
		if err := b.Delete(t.Context(), key); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		_, err := b.Get(t.Context(), key)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("deleting one key leaves the others", func(t *testing.T) {
		b := open(t)
		keys := []string{"key1", "key2"}
		deletedKey := "deleted"
		value := []byte("value")

		mustPut(t, b, deletedKey, value)
		for _, key := range keys {
			mustPut(t, b, key, value)
		}

		if err := b.Delete(t.Context(), deletedKey); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		for _, key := range keys {
			got := mustGet(t, b, key)
			if !bytes.Equal(got, value) {
				t.Errorf("got %x, want %x", got, value)
			}
		}
	})

	t.Run("deleting a key that does not exist is not an error", func(t *testing.T) {
		b := open(t)

		err := b.Delete(t.Context(), "missing")
		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("list returns the keys under a prefix, in order", func(t *testing.T) {
		tests := []struct {
			name   string
			prefix string
			keys   []string
			want   []string
		}{
			{"keys by prefix sorted", "b/",
				[]string{"b/2", "a/1", "b/1", "b/3"},
				[]string{"b/1", "b/2", "b/3"},
			},
			{"keys by prefix not by path", "a",
				[]string{"a/b", "ab", "ba"},
				[]string{"a/b", "ab"},
			},
			{"prefix with no matching keys", "c/",
				[]string{"a/1", "b/1"},
				[]string{},
			},
			{"an empty prefix lists every key", "",
				[]string{"a/1", "b/1", "c/1"},
				[]string{"a/1", "b/1", "c/1"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				b := open(t)
				value := []byte("value")

				for _, key := range tt.keys {
					mustPut(t, b, key, value)
				}

				keys, err := b.List(t.Context(), tt.prefix)
				if err != nil {
					t.Fatalf("List: %v", err)
				}

				if !slices.Equal(keys, tt.want) {
					t.Errorf("got %v, want %v", keys, tt.want)
				}
			})
		}
	})

	t.Run("list does not return deleted keys", func(t *testing.T) {
		b := open(t)
		keys := []string{"a/1", "deleted1", "b/1", "deleted2"}
		deletedKeys := []string{"deleted1", "deleted2"}
		want := []string{"a/1", "b/1"}
		value := []byte("value")

		for _, key := range keys {
			mustPut(t, b, key, value)
		}

		for _, key := range deletedKeys {
			if err := b.Delete(t.Context(), key); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		}

		got, err := b.List(t.Context(), "")
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("closing the backend is not an error", func(t *testing.T) {
		b := open(t)

		err := b.Close()
		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})
}

func mustPut(t *testing.T, b storage.Backend, key string, value []byte) {
	t.Helper()

	if err := b.Put(t.Context(), key, value); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func mustGet(t *testing.T, b storage.Backend, key string) []byte {
	t.Helper()

	got, err := b.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return got
}

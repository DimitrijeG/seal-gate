package bolt_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/bolt"
	"github.com/dimitrijegasic/seal-gate/internal/storage/conformance"
)

func TestConformance(t *testing.T) {
	conformance.Run(t, openBackend)
}

func TestBackend(t *testing.T) {
	t.Run("the backend names itself bolt", func(t *testing.T) {
		b := openBackend(t)

		if got := b.Name(); got != "bolt" {
			t.Errorf("got %q, want %q", got, "bolt")
		}
	})

	t.Run("a value put before close reads back after reopening", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.db")
		key := "key"
		value := []byte("value")

		b := openBackendAt(t, path)
		if err := b.Put(t.Context(), key, value); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		reopened := openBackendAt(t, path)
		got, err := reopened.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(got, value) {
			t.Errorf("got %x, want %x", got, value)
		}
	})

	t.Run("opening a file another handle holds fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.db")
		openBackendAt(t, path)

		_, err := bolt.Open(path)
		if !errors.Is(err, bolt.ErrLocked) {
			t.Errorf("got %v, want %v", err, bolt.ErrLocked)
		}
	})
}

func openBackend(t *testing.T) storage.Backend {
	t.Helper()
	return openBackendAt(t, filepath.Join(t.TempDir(), "test.db"))
}

// openBackendAt closes the backend on cleanup; closing it earlier is harmless.
func openBackendAt(t *testing.T, path string) storage.Backend {
	t.Helper()
	b, err := bolt.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return b
}

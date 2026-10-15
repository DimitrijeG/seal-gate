package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/conformance"
	"github.com/dimitrijegasic/seal-gate/internal/storage/postgres"
	"github.com/dimitrijegasic/seal-gate/internal/storage/postgres/postgrestest"
)

func TestConformance(t *testing.T) {
	conformance.Run(t, openBackend)
}

func TestBackend(t *testing.T) {
	t.Run("the backend names itself postgres", func(t *testing.T) {
		b := openBackend(t)

		if got := b.Name(); got != "postgres" {
			t.Errorf("got %q, want %q", got, "postgres")
		}
	})

	t.Run("the table survives reopening", func(t *testing.T) {
		connString := postgrestest.SchemaURL(t)
		key := "key"
		value := []byte("value")

		b := openBackendAt(t, connString)
		if err := b.Put(t.Context(), key, value); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		reopened := openBackendAt(t, connString)
		got, err := reopened.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(got, value) {
			t.Errorf("got %x, want %x", got, value)
		}
	})

	t.Run("a cancelled context fails each call", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, b storage.Backend) error
		}{
			{"Get", func(ctx context.Context, b storage.Backend) error {
				_, err := b.Get(ctx, "key")
				return err
			}},
			{"Put", func(ctx context.Context, b storage.Backend) error {
				return b.Put(ctx, "key", []byte("value"))
			}},
			{"Delete", func(ctx context.Context, b storage.Backend) error {
				return b.Delete(ctx, "key")
			}},
			{"List", func(ctx context.Context, b storage.Backend) error {
				_, err := b.List(ctx, "")
				return err
			}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				b := openBackend(t)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				if err := tt.call(ctx, b); !errors.Is(err, context.Canceled) {
					t.Errorf("got %v, want %v", err, context.Canceled)
				}
			})
		}
	})

	t.Run("opening with a cancelled context fails", func(t *testing.T) {
		connString := postgrestest.SchemaURL(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		b, err := postgres.Open(ctx, connString)
		if err == nil {
			b.Close()
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v, want %v", err, context.Canceled)
		}
	})

	t.Run("the password in the URL is not in the error", func(t *testing.T) {
		// Random, so no literal looks like a committed credential.
		password := rand.Text()
		tests := []struct {
			name       string
			connString string
		}{
			{"an unparseable URL", "postgres://seal:" + password + "@127.0.0.1:notaport/db?sslmode=disable"},
			{"an unreachable server", "postgres://seal:" + password + "@127.0.0.1:1/db?sslmode=disable"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Bounded: a refused dial can be slow, and this must not hang CI.
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()

				b, err := postgres.Open(ctx, tt.connString)
				if err == nil {
					b.Close()
					t.Fatal("Open: got nil error, want one")
				}
				if strings.Contains(err.Error(), password) {
					t.Errorf("got %q, want no password", err)
				}
			})
		}
	})
}

func openBackend(t *testing.T) storage.Backend {
	t.Helper()
	return openBackendAt(t, postgrestest.SchemaURL(t))
}

// openBackendAt closes the backend on cleanup; closing it earlier is harmless.
func openBackendAt(t *testing.T, connString string) storage.Backend {
	t.Helper()
	b, err := postgres.Open(t.Context(), connString)
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

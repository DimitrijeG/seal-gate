package app

import (
	"path/filepath"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/storage/postgres/postgrestest"
)

func TestBuildStorage(t *testing.T) {
	t.Run("the bolt type opens a bolt backend", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{
			Type: "bolt",
			Path: filepath.Join(t.TempDir(), "test.db"),
		}}

		backend, err := buildStorage(t.Context(), cfg)
		if err != nil {
			t.Fatalf("buildStorage: %v", err)
		}
		t.Cleanup(func() {
			if err := backend.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})

		if got := backend.Name(); got != "bolt" {
			t.Errorf("got %q, want %q", got, "bolt")
		}
	})

	t.Run("the postgres type opens a postgres backend", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{
			Type: "postgres",
			URL:  postgrestest.SchemaURL(t),
		}}

		backend, err := buildStorage(t.Context(), cfg)
		if err != nil {
			t.Fatalf("buildStorage: %v", err)
		}
		t.Cleanup(func() {
			if err := backend.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})

		if got := backend.Name(); got != "postgres" {
			t.Errorf("got %q, want %q", got, "postgres")
		}
	})
}

package app_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/app"
	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/storage/bolt"
)

func TestApplication(t *testing.T) {
	t.Run("stopping the application releases the bolt file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.db")
		cfg := &config.Config{
			Logger:  config.LoggerConfig{Level: "error", Format: "text"},
			Storage: config.StorageConfig{Type: "bolt", Path: path},
			Crypto:  config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
			HTTP:    config.HTTPConfig{Address: "127.0.0.1:0", GracefulShutdown: time.Second},
		}

		application, err := app.Build(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if err := application.Run(ctx); err != nil {
			t.Fatalf("Run: %v", err)
		}

		backend, err := bolt.Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := backend.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}

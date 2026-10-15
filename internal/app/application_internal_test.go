package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/lifecycle"
	"github.com/dimitrijegasic/seal-gate/internal/storage/bolt"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

func TestApplication(t *testing.T) {
	t.Run("stopping the application releases the bolt file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.db")
		cfg := &config.Config{
			Logger:    config.LoggerConfig{Level: "error", Format: "text"},
			Storage:   config.StorageConfig{Type: "bolt", Path: path},
			Crypto:    config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
			HTTP:      config.HTTPConfig{Address: "127.0.0.1:0", GracefulShutdown: time.Second},
			Audit:     fileAudit(t),
			Lifecycle: config.LifecycleConfig{Interval: time.Hour},
		}

		application, err := Build(t.Context(), cfg)
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

	t.Run("stopping the application seals it", func(t *testing.T) {
		cfg := &config.Config{
			Logger:    config.LoggerConfig{Level: "error", Format: "text"},
			Storage:   config.StorageConfig{Type: "memory"},
			Crypto:    config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
			HTTP:      config.HTTPConfig{Address: "127.0.0.1:0", GracefulShutdown: time.Second},
			Audit:     fileAudit(t),
			Lifecycle: config.LifecycleConfig{Interval: time.Hour},
		}

		application, err := Build(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}

		result, err := application.system.Init(t.Context(), system.SealConfiguration{Shares: 5, Threshold: 3})
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		var status system.Status
		for _, share := range result.Shares[:3] {
			status, err = application.system.Unseal(t.Context(), share)
			if err != nil {
				t.Fatalf("Unseal: %v", err)
			}
		}
		if status.Sealed {
			t.Fatalf("Unseal: still sealed after threshold shares")
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if err := application.Run(ctx); err != nil {
			t.Fatalf("Run: %v", err)
		}

		status, err = application.system.Status(t.Context())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if !status.Sealed {
			t.Errorf("got sealed %v, want true", status.Sealed)
		}
	})

	t.Run("the application seals before it releases the backend", func(t *testing.T) {
		infra, err := buildInfrastructure(&config.Config{
			Logger: config.LoggerConfig{Level: "error", Format: "text"},
			Crypto: config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
		})
		if err != nil {
			t.Fatalf("buildInfrastructure: %v", err)
		}
		auditor, _ := fileAuditor(t, infra.logger)
		services, err := buildServices(infra, buildRepositories(memory.New(), infra), auditor, time.Hour)
		if err != nil {
			t.Fatalf("buildServices: %v", err)
		}

		result, err := services.system.Init(t.Context(), system.SealConfiguration{Shares: 5, Threshold: 3})
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		for _, share := range result.Shares[:3] {
			if _, err := services.system.Unseal(t.Context(), share); err != nil {
				t.Fatalf("Unseal: %v", err)
			}
		}
		if !infra.keys.IsInstalled() {
			t.Fatalf("IsInstalled: got false after unseal, want true")
		}

		var installed bool
		application := &Application{
			system: services.system,
			closers: []func() error{func() error {
				installed = infra.keys.IsInstalled()
				return nil
			}},
		}

		if err := application.close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		if installed {
			t.Errorf("got key installed %v, want false", installed)
		}
	})

	t.Run("a build without audit sinks fails", func(t *testing.T) {
		cfg := &config.Config{
			Logger:  config.LoggerConfig{Level: "error", Format: "text"},
			Storage: config.StorageConfig{Type: "memory"},
			Crypto:  config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
		}

		_, err := Build(t.Context(), cfg)

		if !errors.Is(err, audit.ErrNoSinks) {
			t.Errorf("got %v, want %v", err, audit.ErrNoSinks)
		}
	})

	t.Run("a build with a non-positive lifecycle interval fails", func(t *testing.T) {
		tests := []struct {
			name     string
			interval time.Duration
		}{
			{"zero", 0},
			{"negative", -time.Second},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := &config.Config{
					Logger:    config.LoggerConfig{Level: "error", Format: "text"},
					Storage:   config.StorageConfig{Type: "memory"},
					Crypto:    config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
					Audit:     fileAudit(t),
					Lifecycle: config.LifecycleConfig{Interval: tt.interval},
				}

				_, err := Build(t.Context(), cfg)

				if !errors.Is(err, lifecycle.ErrInvalidInterval) {
					t.Errorf("got %v, want %v", err, lifecycle.ErrInvalidInterval)
				}
			})
		}
	})

	t.Run("a build that fails before the services exist still closes", func(t *testing.T) {
		cfg := &config.Config{
			Logger:  config.LoggerConfig{Level: "error", Format: "text"},
			Storage: config.StorageConfig{Type: "nope"},
			Crypto:  config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
		}

		// The failure under test is a panic in Build's cleanup, not the error.
		if _, err := Build(t.Context(), cfg); err == nil {
			t.Errorf("got nil error, want a storage failure")
		}
	})
}

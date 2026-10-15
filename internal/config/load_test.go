package config_test

import (
	"slices"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/config"
)

func TestLoad(t *testing.T) {
	t.Run("the default config stores in bolt", func(t *testing.T) {
		want := config.StorageConfig{Type: "bolt", Path: "seal-gate.db"}

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got := cfg.Storage; got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the default config audits to one required file", func(t *testing.T) {
		want := []config.AuditSinkConfig{{Type: "file", Path: "seal-gate-audit.log", Required: true, Timeout: time.Second}}

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got := cfg.Audit.Sinks; !slices.Equal(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the default config sweeps every minute", func(t *testing.T) {
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got, want := cfg.Lifecycle.Interval, time.Minute; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the default config issues tokens for an hour", func(t *testing.T) {
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got, want := cfg.Token.DefaultTTL, time.Hour; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the default config caps token TTLs at a day", func(t *testing.T) {
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got, want := cfg.Token.MaxTTL, 24*time.Hour; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

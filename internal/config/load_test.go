package config_test

import (
	"testing"

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
}

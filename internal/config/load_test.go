package config_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/config"
)

func TestLoad(t *testing.T) {
	t.Run("the default config stores in bolt", func(t *testing.T) {
		// Cleared, so a deployment's variable in the developer's shell cannot change the defaults.
		t.Setenv("SEAL_GATE_STORAGE_URL", "")
		want := config.StorageConfig{Type: "bolt", Path: "seal-gate.db"}

		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got := cfg.Storage; got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the environment sets the storage URL", func(t *testing.T) {
		want := "postgres://seal@db.example/seal"
		t.Setenv("SEAL_GATE_STORAGE_URL", want)

		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got := cfg.Storage.URL; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("the environment does not change the storage type", func(t *testing.T) {
		t.Setenv("SEAL_GATE_STORAGE_TYPE", "postgres")

		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got, want := cfg.Storage.Type, "bolt"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("the default config audits to one required file", func(t *testing.T) {
		want := []config.AuditSinkConfig{{Type: "file", Path: "seal-gate-audit.log", Required: true, Timeout: time.Second}}

		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got := cfg.Audit.Sinks; !slices.Equal(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the default config sweeps every minute", func(t *testing.T) {
		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got, want := cfg.Lifecycle.Interval, time.Minute; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the default config issues tokens for an hour", func(t *testing.T) {
		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got, want := cfg.Token.DefaultTTL, time.Hour; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the default config caps token TTLs at a day", func(t *testing.T) {
		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got, want := cfg.Token.MaxTTL, 24*time.Hour; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a missing file fails", func(t *testing.T) {
		_, err := config.Load(filepath.Join(t.TempDir(), "missing.yaml"))

		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("got %v, want %v", err, fs.ErrNotExist)
		}
	})

	t.Run("the file sets each field", func(t *testing.T) {
		tests := []struct {
			name     string
			old, new string
			field    func(*config.Config) any
			want     any
		}{
			{"logger level", "level: info", "level: debug", func(c *config.Config) any { return c.Logger.Level }, "debug"},
			{"logger format", "format: json", "format: text", func(c *config.Config) any { return c.Logger.Format }, "text"},
			{"storage type", "type: bolt", "type: memory", func(c *config.Config) any { return c.Storage.Type }, "memory"},
			{"storage path", "path: seal-gate.db", "path: /var/lib/seal-gate.db", func(c *config.Config) any { return c.Storage.Path }, "/var/lib/seal-gate.db"},
			{"cipher", "aead_algorithm: aes-256-gcm", "aead_algorithm: aes-128-gcm", func(c *config.Config) any { return c.Crypto.AEADAlgorithm }, "aes-128-gcm"},
			{"listen address", "address: 127.0.0.1:8080", "address: 0.0.0.0:8200", func(c *config.Config) any { return c.HTTP.Address }, "0.0.0.0:8200"},
			{"header read timeout", "read_header_timeout: 2s", "read_header_timeout: 3s", func(c *config.Config) any { return c.HTTP.ReadHeaderTimeout }, 3 * time.Second},
			{"read timeout", "read_timeout: 5s", "read_timeout: 30s", func(c *config.Config) any { return c.HTTP.ReadTimeout }, 30 * time.Second},
			{"write timeout", "write_timeout: 5s", "write_timeout: 30s", func(c *config.Config) any { return c.HTTP.WriteTimeout }, 30 * time.Second},
			{"graceful shutdown", "graceful_shutdown: 5s", "graceful_shutdown: 10s", func(c *config.Config) any { return c.HTTP.GracefulShutdown }, 10 * time.Second},
			{"lifecycle interval", "interval: 1m", "interval: 5m", func(c *config.Config) any { return c.Lifecycle.Interval }, 5 * time.Minute},
			{"default token TTL", "default_ttl: 1h", "default_ttl: 15m", func(c *config.Config) any { return c.Token.DefaultTTL }, 15 * time.Minute},
			{"max token TTL", "max_ttl: 24h", "max_ttl: 12h", func(c *config.Config) any { return c.Token.MaxTTL }, 12 * time.Hour},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				path := writeConfig(t, defaultWith(t, tc.old, tc.new))

				cfg, err := config.Load(path)
				if err != nil {
					t.Fatalf("Load: %v", err)
				}

				if got := tc.field(cfg); got != tc.want {
					t.Errorf("got %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("the file sets the audit sinks", func(t *testing.T) {
		path := writeConfig(t, defaultWith(t, "path: seal-gate-audit.log", "path: /var/log/seal-gate.log"))
		want := []config.AuditSinkConfig{{Type: "file", Path: "/var/log/seal-gate.log", Required: true, Timeout: time.Second}}

		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if got := cfg.Audit.Sinks; !slices.Equal(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a file that leaves out a field fails", func(t *testing.T) {
		tests := []struct {
			name, old string
		}{
			{"section", "lifecycle:\n  interval: 1m"},
			{"field", "  read_timeout: 5s\n"},
			{"sink field", "      timeout: 1s\n"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				path := writeConfig(t, defaultWith(t, tc.old, ""))

				_, err := config.Load(path)

				if !errors.Is(err, config.ErrMissingField) {
					t.Errorf("got %v, want %v", err, config.ErrMissingField)
				}
			})
		}
	})

	t.Run("a file that leaves a field empty fails", func(t *testing.T) {
		tests := []struct {
			name, old, new string
		}{
			{"blank flag", "required: true", "required:"},
			{"null flag", "required: true", "required: null"},
			{"null duration", "read_timeout: 5s", "read_timeout: null"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				path := writeConfig(t, defaultWith(t, tc.old, tc.new))

				_, err := config.Load(path)

				if !errors.Is(err, config.ErrMissingField) {
					t.Errorf("got %v, want %v", err, config.ErrMissingField)
				}
			})
		}
	})

	t.Run("a text field given another type fails", func(t *testing.T) {
		tests := []struct {
			name, old, new string
		}{
			{"number", "path: seal-gate.db", "path: 123"},
			{"boolean", "format: json", "format: false"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				path := writeConfig(t, defaultWith(t, tc.old, tc.new))

				_, err := config.Load(path)

				if !errors.Is(err, config.ErrInvalidFile) {
					t.Errorf("got %v, want %v", err, config.ErrInvalidFile)
				}
			})
		}
	})

	t.Run("a file that reuses a value fails", func(t *testing.T) {
		tests := []struct {
			name, file string
		}{
			{"alias", strings.Replace(defaultWith(t, "path: seal-gate.db", "path: &db seal-gate.db"), "path: seal-gate-audit.log", "path: *db", 1)},
			{"merge key", defaultWith(t, "aead_algorithm: aes-256-gcm", "<<: {aead_algorithm: aes-256-gcm}")},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				path := writeConfig(t, tc.file)

				_, err := config.Load(path)

				if !errors.Is(err, config.ErrInvalidFile) {
					t.Errorf("got %v, want %v", err, config.ErrInvalidFile)
				}
			})
		}
	})

	t.Run("an empty file fails", func(t *testing.T) {
		path := writeConfig(t, "")

		_, err := config.Load(path)

		if !errors.Is(err, config.ErrMissingField) {
			t.Errorf("got %v, want %v", err, config.ErrMissingField)
		}
	})

	t.Run("an unknown field fails", func(t *testing.T) {
		path := writeConfig(t, defaultWith(t, "address:", "adress:"))

		_, err := config.Load(path)

		if !errors.Is(err, config.ErrInvalidFile) {
			t.Errorf("got %v, want %v", err, config.ErrInvalidFile)
		}
	})

	t.Run("a value of the wrong type fails", func(t *testing.T) {
		path := writeConfig(t, defaultWith(t, "required: true", "required: maybe"))

		_, err := config.Load(path)

		if !errors.Is(err, config.ErrInvalidFile) {
			t.Errorf("got %v, want %v", err, config.ErrInvalidFile)
		}
	})

	t.Run("a duration written as a number fails", func(t *testing.T) {
		path := writeConfig(t, defaultWith(t, "interval: 1m", "interval: 60"))

		_, err := config.Load(path)

		if !errors.Is(err, config.ErrInvalidFile) {
			t.Errorf("got %v, want %v", err, config.ErrInvalidFile)
		}
	})

	t.Run("a second document fails", func(t *testing.T) {
		path := writeConfig(t, defaultFile(t)+"---\nhttp:\n  adress: 0.0.0.0:8200\n")

		_, err := config.Load(path)

		if !errors.Is(err, config.ErrInvalidFile) {
			t.Errorf("got %v, want %v", err, config.ErrInvalidFile)
		}
	})

	t.Run("the file cannot set the storage URL", func(t *testing.T) {
		path := writeConfig(t, defaultWith(t, "path: seal-gate.db", "path: seal-gate.db\n  url: postgres://seal:hunter2@db.example/seal"))

		_, err := config.Load(path)

		if !errors.Is(err, config.ErrInvalidFile) {
			t.Errorf("got %v, want %v", err, config.ErrInvalidFile)
		}
	})

	t.Run("a refused storage URL stays out of the error", func(t *testing.T) {
		path := writeConfig(t, defaultWith(t, "path: seal-gate.db", "path: seal-gate.db\n  url: postgres://seal:hunter2@db.example/seal"))

		_, err := config.Load(path)
		if err == nil {
			t.Fatal("Load: got nil, want an error")
		}

		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("got %q, want no password", err)
		}
	})
}

// defaultFile is the shipped default, so each test file differs from a complete one in a single place.
func defaultFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("default.yaml")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(data)
}

func defaultWith(t *testing.T, old, new string) string {
	t.Helper()
	file := defaultFile(t)
	if strings.Count(file, old) != 1 {
		t.Fatalf("default.yaml holds %q %d times, want once", old, strings.Count(file, old))
	}
	return strings.Replace(file, old, new, 1)
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seal-gate.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

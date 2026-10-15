package config

import (
	"os"
	"time"
)

// Load returns built-in defaults, with the storage type and URL taken from the environment when set.
func Load() (*Config, error) {
	cfg := &Config{
		Logger: LoggerConfig{
			Level:  "info",
			Format: "json",
		},
		Storage: StorageConfig{
			Type: "bolt",
			Path: "seal-gate.db",
		},
		Crypto: CryptoConfig{
			AEADAlgorithm: "aes-256-gcm",
		},
		HTTP: HTTPConfig{
			Address:           "127.0.0.1:8080",
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			GracefulShutdown:  5 * time.Second,
		},
		Audit: AuditConfig{
			Sinks: []AuditSinkConfig{
				{Type: "file", Path: "seal-gate-audit.log", Required: true, Timeout: time.Second},
			},
		},
		Lifecycle: LifecycleConfig{
			Interval: time.Minute,
		},
		Token: TokenConfig{
			DefaultTTL: time.Hour,
			MaxTTL:     24 * time.Hour,
		},
	}

	if storageType := os.Getenv("SEAL_GATE_STORAGE_TYPE"); storageType != "" {
		cfg.Storage.Type = storageType
	}
	cfg.Storage.URL = os.Getenv("SEAL_GATE_STORAGE_URL")
	return cfg, nil
}

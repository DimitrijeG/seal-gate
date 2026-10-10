package config

import "time"

// Load returns built-in defaults until a configuration source exists.
func Load() (*Config, error) {
	return &Config{
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
	}, nil
}

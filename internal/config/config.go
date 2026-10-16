// Package config loads and validates typed configuration; beyond the storage URL's password, it holds no keys, shares, secrets or tokens.
package config

import "time"

// Config is the whole service configuration, as Load returns it.
type Config struct {
	Logger    LoggerConfig    `yaml:"logger"`
	Storage   StorageConfig   `yaml:"storage"`
	Crypto    CryptoConfig    `yaml:"crypto"`
	HTTP      HTTPConfig      `yaml:"http"`
	Audit     AuditConfig     `yaml:"audit"`
	Lifecycle LifecycleConfig `yaml:"lifecycle"`
	Token     TokenConfig     `yaml:"token"`
}

// LoggerConfig sets the level, as slog.Level parses it ("info", "warn+2"), and the format ("text", else JSON).
type LoggerConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// StorageConfig picks the backend ("memory", "bolt" or "postgres"), and bolt's file or postgres's connection URL.
type StorageConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
	// URL may carry the database password, so it is never logged or put in an error, and comes only from the environment.
	URL string `yaml:"-"`
}

// CryptoConfig names the AEAD that encrypts stored records and wraps the barrier key ("aes-256-gcm").
type CryptoConfig struct {
	AEADAlgorithm string `yaml:"aead_algorithm"`
}

// HTTPConfig is the listen address, the http.Server timeouts, and the shutdown grace period.
type HTTPConfig struct {
	Address           string        `yaml:"address"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	GracefulShutdown  time.Duration `yaml:"graceful_shutdown"`
}

// AuditConfig names the sinks every audit event is written to.
type AuditConfig struct {
	Sinks []AuditSinkConfig `yaml:"sinks"`
}

// AuditSinkConfig is one audit sink: its type ("file"), where it writes, whether its failure fails the request, and how long a write may take.
type AuditSinkConfig struct {
	Type     string        `yaml:"type"`
	Path     string        `yaml:"path"`
	Required bool          `yaml:"required"`
	Timeout  time.Duration `yaml:"timeout"`
}

// LifecycleConfig is how often the lifecycle worker sweeps for secrets to rotate or expire.
type LifecycleConfig struct {
	Interval time.Duration `yaml:"interval"`
}

// TokenConfig is how long an issued token lives when no TTL is asked for, and the longest TTL that may be.
type TokenConfig struct {
	DefaultTTL time.Duration `yaml:"default_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
}

// Package config loads and validates typed configuration; beyond the storage URL's password, it holds no keys, shares, secrets or tokens.
package config

import "time"

// Config is the whole service configuration, as Load returns it.
type Config struct {
	Logger    LoggerConfig
	Storage   StorageConfig
	Crypto    CryptoConfig
	HTTP      HTTPConfig
	Audit     AuditConfig
	Lifecycle LifecycleConfig
	Token     TokenConfig
}

// LoggerConfig sets the level, as slog.Level parses it ("info", "warn+2"), and the format ("text", else JSON).
type LoggerConfig struct {
	Level  string
	Format string
}

// StorageConfig picks the backend ("memory", "bolt" or "postgres"), and bolt's file or postgres's connection URL.
type StorageConfig struct {
	Type string
	Path string
	// URL may carry the database password, so it is never logged or put in an error.
	URL string
}

// CryptoConfig names the AEAD that encrypts stored records and wraps the barrier key ("aes-256-gcm").
type CryptoConfig struct {
	AEADAlgorithm string
}

// HTTPConfig is the listen address, the http.Server timeouts, and the shutdown grace period.
type HTTPConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	GracefulShutdown  time.Duration
}

// AuditConfig names the sinks every audit event is written to.
type AuditConfig struct {
	Sinks []AuditSinkConfig
}

// AuditSinkConfig is one audit sink: its type ("file"), where it writes, whether its failure fails the request, and how long a write may take.
type AuditSinkConfig struct {
	Type     string
	Path     string
	Required bool
	Timeout  time.Duration
}

// LifecycleConfig is how often the lifecycle worker sweeps for secrets to rotate or expire.
type LifecycleConfig struct {
	Interval time.Duration
}

// TokenConfig is how long an issued token lives when no TTL is asked for, and the longest TTL that may be.
type TokenConfig struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// Package config loads and validates typed configuration; it never holds keys, shares, secrets or tokens.
package config

import "time"

type Config struct {
	Logger  LoggerConfig
	Storage StorageConfig
	Crypto  CryptoConfig
	HTTP    HTTPConfig
	Audit   AuditConfig
}

type LoggerConfig struct {
	Level  string
	Format string
}

type StorageConfig struct {
	Type string
	Path string
}

type CryptoConfig struct {
	AEADAlgorithm string
}

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

package config

import "time"

type Config struct {
	Logger  LoggerConfig
	Storage StorageConfig
	Crypto  CryptoConfig
	HTTP    HTTPConfig
}

type LoggerConfig struct {
	Level  string
	Format string
}

type StorageConfig struct {
	Type string
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

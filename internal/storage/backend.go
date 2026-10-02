// Package storage defines the key-value contract every physical backend implements.
package storage

type Backend interface {
	Name() string
	Close() error
}

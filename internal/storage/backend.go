package storage

type Backend interface {
	Name() string
	Close() error
}

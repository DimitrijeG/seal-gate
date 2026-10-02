// Package memory is an in-process storage backend for tests and development; nothing survives a restart.
package memory

type Backend struct{}

func New() *Backend {
	return &Backend{}
}

func (m *Backend) Name() string {
	return "memory"
}

func (m *Backend) Close() error {
	return nil
}

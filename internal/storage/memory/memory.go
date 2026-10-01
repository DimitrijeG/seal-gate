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

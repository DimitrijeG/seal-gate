package app

import (
	"context"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

type backendFactory func(ctx context.Context, cfg *config.Config) (storage.Backend, error)

// backendFactories keeps backend selection to one lookup instead of a switch
// repeated wherever a backend is named.
var backendFactories = map[string]backendFactory{
	"memory": openMemory,
}

func buildStorage(ctx context.Context, cfg *config.Config) (storage.Backend, error) {
	factory, ok := backendFactories[cfg.Storage.Type]
	if !ok {
		return nil, fmt.Errorf("app: unsupported storage backend %q", cfg.Storage.Type)
	}
	return factory(ctx, cfg)
}

func openMemory(context.Context, *config.Config) (storage.Backend, error) {
	return memory.New(), nil
}

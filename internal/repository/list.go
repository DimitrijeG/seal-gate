package repository

import (
	"context"
	"strings"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
)

// listNames returns the keys under prefix with it trimmed; the barrier's error is returned as is, for the caller to map.
func listNames(ctx context.Context, encrypted *barrier.AEADBarrier, prefix string) ([]string, error) {
	keys, err := encrypted.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(keys))
	for i, key := range keys {
		names[i] = strings.TrimPrefix(key, prefix)
	}
	return names, nil
}

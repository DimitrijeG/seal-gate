package app

import (
	"context"
	"fmt"
	"slices"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

// unsealedResources activates its members in order and deactivates them in reverse, so a later one may use an earlier.
type unsealedResources []system.UnsealedResource

var _ system.UnsealedResource = unsealedResources(nil)

func (r unsealedResources) Activate(ctx context.Context) error {
	for i, resource := range r {
		if err := resource.Activate(ctx); err != nil {
			for _, active := range slices.Backward(r[:i]) {
				active.Deactivate()
			}
			return fmt.Errorf("app: %w", err)
		}
	}
	return nil
}

func (r unsealedResources) Deactivate() {
	for _, resource := range slices.Backward(r) {
		resource.Deactivate()
	}
}

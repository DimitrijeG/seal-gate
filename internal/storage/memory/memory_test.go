package memory_test

import (
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/conformance"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

func TestConformance(t *testing.T) {
	conformance.Run(t, func(*testing.T) storage.Backend {
		return memory.New()
	})
}

func TestBackend(t *testing.T) {
	t.Run("the backend names itself memory", func(t *testing.T) {
		var b storage.Backend = memory.New()

		if got := b.Name(); got != "memory" {
			t.Errorf("got %q, want %q", got, "memory")
		}
	})
}

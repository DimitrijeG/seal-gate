package app

import (
	"context"
	"errors"
	"slices"
	"testing"
)

var errActivate = errors.New("activate failed")

// recordingResource appends each call to a log shared with its siblings, so their order is one slice.
type recordingResource struct {
	name string
	log  *[]string
	err  error
}

func (r *recordingResource) Activate(context.Context) error {
	*r.log = append(*r.log, "activate "+r.name)
	return r.err
}

func (r *recordingResource) Deactivate() {
	*r.log = append(*r.log, "deactivate "+r.name)
}

func TestUnsealedResources(t *testing.T) {
	t.Run("the composite activates in order", func(t *testing.T) {
		var log []string
		resources := unsealedResources{
			&recordingResource{name: "a", log: &log},
			&recordingResource{name: "b", log: &log},
		}

		if err := resources.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}

		want := []string{"activate a", "activate b"}
		if !slices.Equal(log, want) {
			t.Errorf("got %v, want %v", log, want)
		}
	})

	t.Run("a failed activation returns its error", func(t *testing.T) {
		var log []string
		resources := unsealedResources{
			&recordingResource{name: "a", log: &log},
			&recordingResource{name: "b", log: &log, err: errActivate},
		}

		err := resources.Activate(t.Context())

		if !errors.Is(err, errActivate) {
			t.Errorf("got %v, want %v", err, errActivate)
		}
	})

	t.Run("a failed activation does not activate the rest", func(t *testing.T) {
		var log []string
		resources := unsealedResources{
			&recordingResource{name: "a", log: &log, err: errActivate},
			&recordingResource{name: "b", log: &log},
		}

		_ = resources.Activate(t.Context())

		if slices.Contains(log, "activate b") {
			t.Errorf("got %v, want no activate b", log)
		}
	})

	t.Run("a failed activation deactivates the ones already active, in reverse", func(t *testing.T) {
		var log []string
		resources := unsealedResources{
			&recordingResource{name: "a", log: &log},
			&recordingResource{name: "b", log: &log},
			&recordingResource{name: "c", log: &log, err: errActivate},
		}

		_ = resources.Activate(t.Context())

		want := []string{"activate a", "activate b", "activate c", "deactivate b", "deactivate a"}
		if !slices.Equal(log, want) {
			t.Errorf("got %v, want %v", log, want)
		}
	})

	t.Run("the composite deactivates in reverse", func(t *testing.T) {
		var log []string
		resources := unsealedResources{
			&recordingResource{name: "a", log: &log},
			&recordingResource{name: "b", log: &log},
		}

		resources.Deactivate()

		want := []string{"deactivate b", "deactivate a"}
		if !slices.Equal(log, want) {
			t.Errorf("got %v, want %v", log, want)
		}
	})
}

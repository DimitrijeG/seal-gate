// Package audit owns audit events and their fan-out to sinks.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

var (
	ErrNoSinks = errors.New("audit: no sinks")
	ErrNilSink = errors.New("audit: destination has no sink")
)

// Kind says whether an event records a request before it runs or its response after.
type Kind string

const (
	KindRequest  Kind = "request"
	KindResponse Kind = "response"
)

// Event is one audit record. Its fields are request metadata only, so no secret, token or share can be put in one.
type Event struct {
	Time      time.Time
	RequestID string
	Kind      Kind
	Principal string
	Method    string
	Route     string
	Path      string
	Status    int
}

// Sink receives events; it must be safe for concurrent use.
type Sink interface {
	Write(ctx context.Context, event Event) error
}

// Destination is one sink, whether its failure fails Record, and how long a write may take.
type Destination struct {
	Name     string
	Sink     Sink
	Required bool
	Timeout  time.Duration
}

// FanOut records each event to every destination; it is safe for concurrent use.
type FanOut struct {
	logger       *slog.Logger
	destinations []Destination
}

// New returns a FanOut over its own copy of destinations; it refuses none and a destination without a sink.
func New(logger *slog.Logger, destinations ...Destination) (*FanOut, error) {
	if len(destinations) == 0 {
		return nil, ErrNoSinks
	}
	for _, d := range destinations {
		if d.Sink == nil {
			return nil, ErrNilSink
		}
	}
	return &FanOut{logger: logger, destinations: slices.Clone(destinations)}, nil
}

// Record writes event to every destination, even after one fails. A required failure fails it; an optional one is logged.
func (f *FanOut) Record(ctx context.Context, event Event) error {
	var failures []error
	for _, d := range f.destinations {
		err := d.Sink.Write(ctx, event)
		if err == nil {
			continue
		}
		if d.Required {
			failures = append(failures, fmt.Errorf("audit: sink %q: %w", d.Name, err))
			continue
		}
		f.logger.Warn("audit sink failed", "sink", d.Name, "error", err)
	}
	return errors.Join(failures...)
}

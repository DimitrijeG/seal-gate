// Package audit owns audit events and their fan-out to sinks.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	ErrNoSinks        = errors.New("audit: no sinks")
	ErrNilSink        = errors.New("audit: destination has no sink")
	ErrInvalidTimeout = errors.New("audit: destination timeout must be positive")
)

// Kind says whether an event records a request before it runs, its response after, or an action the lifecycle
// worker took with no request behind it.
type Kind string

const (
	KindRequest   Kind = "request"
	KindResponse  Kind = "response"
	KindLifecycle Kind = "lifecycle"
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
	destinations []destination
}

// destination holds one write slot, so a sink stuck in a write is not handed
// another: a hung sink then costs one goroutine, not one per request.
type destination struct {
	Destination
	slot chan struct{}
}

// New returns a FanOut over its own copy of destinations; it refuses none, and any without a sink or a positive timeout.
func New(logger *slog.Logger, destinations ...Destination) (*FanOut, error) {
	if len(destinations) == 0 {
		return nil, ErrNoSinks
	}
	owned := make([]destination, 0, len(destinations))
	for _, d := range destinations {
		if d.Sink == nil {
			return nil, ErrNilSink
		}
		if d.Timeout <= 0 {
			return nil, ErrInvalidTimeout
		}
		owned = append(owned, destination{Destination: d, slot: make(chan struct{}, 1)})
	}
	return &FanOut{logger: logger, destinations: owned}, nil
}

// Record writes event to every destination, even after one fails. A required failure fails it; an optional one is logged.
func (f *FanOut) Record(ctx context.Context, event Event) error {
	var failures []error
	for _, d := range f.destinations {
		err := write(ctx, d, event)
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

// write bounds the sink by its timeout even if it ignores ctx, as a file write cannot be cancelled.
func write(ctx context.Context, d destination, event Event) error {
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	// Waiting for the slot spends this write's own timeout, so a stuck sink fails it here.
	select {
	case d.slot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Buffered, so a write that finishes after the deadline does not block forever.
	result := make(chan error, 1)
	go func() {
		// The slot is freed only when the sink returns, however late.
		defer func() { <-d.slot }()
		result <- d.Sink.Write(ctx, event)
	}()

	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Package lifecycle owns when expiry and rotation happen: a worker that sweeps on a ticker while unsealed.
package lifecycle

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

var ErrInvalidInterval = errors.New("lifecycle: interval must be positive")

// principal is who the audit trail says acted: the worker, with no entity behind it.
const principal = "lifecycle"

// secretResource turns a secret path into the resource name policies and the audit trail use for it.
const secretResource = "secrets/"

// operations names each action in the audit trail's route field, where a request's route would be.
var operations = map[secret.ActionKind]string{
	secret.ActionRotated: "rotate secret",
	secret.ActionExpired: "expire secret",
}

// Sweeper rotates and expires what is due, reporting what it did even beside an error.
type Sweeper interface {
	Sweep(ctx context.Context) ([]secret.Action, error)
}

// Recorder writes one audit event; Tick logs a failure rather than retrying, as the action already happened.
type Recorder interface {
	Record(ctx context.Context, event audit.Event) error
}

// Clock is the time each event is stamped with, so tests can fix it.
type Clock interface {
	Now() time.Time
}

// Worker sweeps once per interval while active and audits each action. Activate and Deactivate alternate, never
// concurrently: the seal lifecycle calls them under its own lock.
type Worker struct {
	interval time.Duration
	sweeper  Sweeper
	recorder Recorder
	clock    Clock
	logger   *slog.Logger
	cancel   context.CancelFunc
	done     chan struct{}
}

// New returns an inactive Worker; a non-positive interval is ErrInvalidInterval.
func New(interval time.Duration, sweeper Sweeper, recorder Recorder, clock Clock, logger *slog.Logger) (*Worker, error) {
	if interval <= 0 {
		return nil, ErrInvalidInterval
	}
	return &Worker{interval: interval, sweeper: sweeper, recorder: recorder, clock: clock, logger: logger}, nil
}

// Tick runs one sweep and records an event per action; failures are logged, since no caller is waiting on a tick.
func (w *Worker) Tick(ctx context.Context) {
	actions, err := w.sweeper.Sweep(ctx)
	// Not cancelled with the sweep: what it did before a deactivate still happened. Each sink bounds its own write.
	recordCtx := context.WithoutCancel(ctx)
	// One ID per tick, so the trail groups what one sweep did.
	id := rand.Text()
	for _, action := range actions {
		event := audit.Event{
			Time:      w.clock.Now(),
			RequestID: id,
			Kind:      audit.KindLifecycle,
			Principal: principal,
			Route:     operations[action.Kind],
			Path:      secretResource + action.Path,
		}
		// Logged, not retried: the action has already happened.
		if err := w.recorder.Record(recordCtx, event); err != nil {
			w.logger.Error("lifecycle audit failed", "route", event.Route, "path", event.Path, "error", err)
		}
	}
	// After the records: what the sweep did before failing still happened.
	if err != nil {
		w.logger.Error("lifecycle sweep failed", "error", err)
	}
}

// Activate starts ticking until Deactivate. Its context is not the loop's: that is the unseal request's, done once
// its response is sent.
func (w *Worker) Activate(context.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	w.cancel, w.done = cancel, done
	go func() {
		defer close(done)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.Tick(ctx)
			}
		}
	}()
	return nil
}

// Deactivate stops ticking and returns once no tick is running; on an inactive worker it does nothing.
func (w *Worker) Deactivate() {
	if w.cancel == nil {
		return
	}
	// Cancel before waiting: a tick in flight stops at its next path instead of finishing the sweep.
	w.cancel()
	<-w.done
	w.cancel, w.done = nil, nil
}

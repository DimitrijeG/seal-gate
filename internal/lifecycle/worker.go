// Package lifecycle owns when expiry and rotation happen: a worker that runs its jobs on a ticker while unsealed.
package lifecycle

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
)

var ErrInvalidInterval = errors.New("lifecycle: interval must be positive")

// principal is who the audit trail says acted: the worker, with no entity behind it.
const principal = "lifecycle"

// Action is one change a job made, as the audit trail names it: the operation where a request's route would be, and
// the resource acted on, empty when its only name must not be logged.
type Action struct {
	Operation string
	Resource  string
}

// Job does what is due, reporting each action it took even if it then fails.
type Job interface {
	Run(ctx context.Context, report func(Action)) error
}

// Recorder writes one audit event; Tick logs a failure rather than retrying, as the action already happened.
type Recorder interface {
	Record(ctx context.Context, event audit.Event) error
}

// Clock is the time each event is stamped with, so tests can fix it.
type Clock interface {
	Now() time.Time
}

// Worker runs its jobs once per interval while active and audits each action. Activate and Deactivate alternate,
// never concurrently: the seal lifecycle calls them under its own lock.
type Worker struct {
	interval time.Duration
	jobs     []Job
	recorder Recorder
	clock    Clock
	logger   *slog.Logger
	cancel   context.CancelFunc
	done     chan struct{}
}

// New returns an inactive Worker running jobs in order; a non-positive interval is ErrInvalidInterval.
func New(interval time.Duration, jobs []Job, recorder Recorder, clock Clock, logger *slog.Logger) (*Worker, error) {
	if interval <= 0 {
		return nil, ErrInvalidInterval
	}
	return &Worker{interval: interval, jobs: jobs, recorder: recorder, clock: clock, logger: logger}, nil
}

// Tick runs every job and records an event per action; failures are logged, since no caller is waiting on a tick.
func (w *Worker) Tick(ctx context.Context) {
	// Not cancelled with the jobs: what they did before a deactivate still happened. Each sink bounds its own write.
	recordCtx := context.WithoutCancel(ctx)
	// One ID per tick, so the trail groups what all its jobs did.
	id := rand.Text()
	// Recorded as each action happens, so a deactivate waits on one record at most, not on a whole job's.
	report := func(action Action) {
		event := audit.Event{
			Time:      w.clock.Now(),
			RequestID: id,
			Kind:      audit.KindLifecycle,
			Principal: principal,
			Route:     action.Operation,
			Path:      action.Resource,
		}
		// Logged, not retried: the action has already happened.
		if err := w.recorder.Record(recordCtx, event); err != nil {
			w.logger.Error("lifecycle audit failed", "route", event.Route, "path", event.Path, "error", err)
		}
	}
	for _, job := range w.jobs {
		// Logged and passed over: one job's failure says nothing about the next one's records.
		if err := job.Run(ctx, report); err != nil {
			w.logger.Error("lifecycle job failed", "error", err)
		}
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
	// Cancel before waiting: a tick in flight stops at its next item instead of finishing its jobs.
	w.cancel()
	<-w.done
	w.cancel, w.done = nil, nil
}

package lifecycle_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/lifecycle"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

// fakeSweeper reports actions and returns err from every sweep and counts them; swept, when set, is sent each
// sweep's context without blocking. Locked: the worker sweeps from its own goroutine.
type fakeSweeper struct {
	mu      sync.Mutex
	actions []secret.Action
	err     error
	calls   int
	swept   chan context.Context
}

func (s *fakeSweeper) Sweep(ctx context.Context, report func(secret.Action)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	select {
	case s.swept <- ctx:
	default:
	}
	for _, action := range s.actions {
		report(action)
	}
	return s.err
}

func (s *fakeSweeper) sweeps() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// fakeRecorder keeps every event; err, when set, fails every call, and a done context fails it as the fan-out's does.
type fakeRecorder struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (r *fakeRecorder) Record(ctx context.Context, event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.events = append(r.events, event)
	return nil
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type fixture struct {
	worker   *lifecycle.Worker
	sweeper  *fakeSweeper
	recorder *fakeRecorder
	clock    *fakeClock
	log      *bytes.Buffer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{
		sweeper:  &fakeSweeper{},
		recorder: &fakeRecorder{},
		clock:    &fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		log:      &bytes.Buffer{},
	}
	worker, err := lifecycle.New(time.Minute, f.sweeper, f.recorder, f.clock, slog.New(slog.NewTextHandler(f.log, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.worker = worker
	return f
}

func TestWorker(t *testing.T) {
	t.Run("a tick sweeps", func(t *testing.T) {
		f := newFixture(t)

		f.worker.Tick(t.Context())

		if got := f.sweeper.sweeps(); got != 1 {
			t.Errorf("got %d sweeps, want 1", got)
		}
	})

	t.Run("each action is audited", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions

		f.worker.Tick(t.Context())

		if got := len(f.recorder.events); got != 2 {
			t.Errorf("got %d events, want 2", got)
		}
	})

	t.Run("an event names the secret's resource as its path", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions

		f.worker.Tick(t.Context())

		want := []string{"secrets/api/key", "secrets/db/password"}
		if got := eventField(f.recorder.events, func(e audit.Event) string { return e.Path }); !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an event names its operation", func(t *testing.T) {
		tests := []struct {
			name string
			kind secret.ActionKind
			want string
		}{
			{"rotated", secret.ActionRotated, "rotate secret"},
			{"expired", secret.ActionExpired, "expire secret"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFixture(t)
				f.sweeper.actions = []secret.Action{{Path: "db/password", Kind: tt.kind}}

				f.worker.Tick(t.Context())

				want := []string{tt.want}
				if got := eventField(f.recorder.events, func(e audit.Event) string { return e.Route }); !slices.Equal(got, want) {
					t.Errorf("got %v, want %v", got, want)
				}
			})
		}
	})

	t.Run("an event is recorded as the lifecycle", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions[:1]

		f.worker.Tick(t.Context())

		want := audit.Event{Kind: audit.KindLifecycle, Principal: "lifecycle"}
		got := audit.Event{Kind: f.recorder.events[0].Kind, Principal: f.recorder.events[0].Principal}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("an event is stamped with the clock's time", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions[:1]

		f.worker.Tick(t.Context())

		if got := f.recorder.events[0].Time; !got.Equal(f.clock.now) {
			t.Errorf("got %v, want %v", got, f.clock.now)
		}
	})

	t.Run("a tick's events share one request ID", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions

		f.worker.Tick(t.Context())

		if first, second := f.recorder.events[0].RequestID, f.recorder.events[1].RequestID; first != second {
			t.Errorf("got %q and %q, want one ID", first, second)
		}
	})

	t.Run("two ticks have different request IDs", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions[:1]

		f.worker.Tick(t.Context())
		f.worker.Tick(t.Context())

		if first, second := f.recorder.events[0].RequestID, f.recorder.events[1].RequestID; first == "" || first == second {
			t.Errorf("got %q and %q, want two different IDs", first, second)
		}
	})

	t.Run("actions before a failed sweep are still audited", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions
		f.sweeper.err = errors.New("disk failed")

		f.worker.Tick(t.Context())

		if got := len(f.recorder.events); got != 2 {
			t.Errorf("got %d events, want 2", got)
		}
	})

	t.Run("actions before a cancelled sweep are still audited", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions[:1]
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		f.worker.Tick(ctx)

		if got := len(f.recorder.events); got != 1 {
			t.Errorf("got %d events, want 1", got)
		}
	})

	t.Run("a cancel during a record stops the sweep after it", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		recorder := &cancellingRecorder{cancel: cancel}
		worker, err := lifecycle.New(time.Minute, &cancellableSweeper{actions: twoActions}, recorder, f.clock, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		worker.Tick(ctx)

		if got := len(recorder.events); got != 1 {
			t.Errorf("got %d events, want 1", got)
		}
	})

	t.Run("a failed sweep is logged", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.err = errors.New("disk failed")

		f.worker.Tick(t.Context())

		if got := f.log.String(); !strings.Contains(got, "disk failed") {
			t.Errorf("got log %q, want the sweep's error", got)
		}
	})

	t.Run("a failed record is logged", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions[:1]
		f.recorder.err = errors.New("sink failed")

		f.worker.Tick(t.Context())

		if got := f.log.String(); !strings.Contains(got, "sink failed") {
			t.Errorf("got log %q, want the record's error", got)
		}
	})

	t.Run("a failed record does not stop the rest", func(t *testing.T) {
		f := newFixture(t)
		f.sweeper.actions = twoActions
		recorder := &failFirstRecorder{}
		worker, err := lifecycle.New(time.Minute, f.sweeper, recorder, f.clock, slog.New(slog.NewTextHandler(f.log, nil)))
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		worker.Tick(t.Context())

		if got := len(recorder.events); got != 1 {
			t.Errorf("got %d events, want 1", got)
		}
	})

	t.Run("a non-positive interval is refused", func(t *testing.T) {
		tests := []struct {
			name     string
			interval time.Duration
		}{
			{"zero", 0},
			{"negative", -time.Second},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFixture(t)

				_, err := lifecycle.New(tt.interval, f.sweeper, f.recorder, f.clock, slog.Default())

				if !errors.Is(err, lifecycle.ErrInvalidInterval) {
					t.Errorf("got %v, want %v", err, lifecycle.ErrInvalidInterval)
				}
			})
		}
	})

	t.Run("activate starts ticking", func(t *testing.T) {
		worker, sweeper := newTickingWorker(t)

		activate(t, worker, t.Context())

		awaitSweep(t, sweeper)
	})

	t.Run("ticking outlives the activating context", func(t *testing.T) {
		worker, sweeper := newTickingWorker(t)
		ctx, cancel := context.WithCancel(t.Context())
		activate(t, worker, ctx)
		cancel()
		// Drain a sweep that may have started before the cancel.
		awaitSweep(t, sweeper)

		if err := awaitSweep(t, sweeper).Err(); err != nil {
			t.Errorf("got %v, want a live context", err)
		}
	})

	t.Run("deactivate stops ticking", func(t *testing.T) {
		worker, sweeper := newTickingWorker(t)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		awaitSweep(t, sweeper)

		worker.Deactivate()
		before := sweeper.sweeps()
		time.Sleep(20 * time.Millisecond)

		if got := sweeper.sweeps(); got != before {
			t.Errorf("got %d sweeps, want %d", got, before)
		}
	})

	t.Run("deactivate cancels a tick in flight", func(t *testing.T) {
		sweeper := &blockingSweeper{started: make(chan struct{})}
		worker := newWorkerOver(t, sweeper)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		<-sweeper.started

		deactivated := make(chan struct{})
		go func() {
			worker.Deactivate()
			close(deactivated)
		}()

		select {
		case <-deactivated:
		case <-time.After(time.Second):
			t.Fatal("deactivate still waiting, want the tick cancelled")
		}
	})

	t.Run("deactivate waits for a tick in flight", func(t *testing.T) {
		sweeper := &blockingSweeper{started: make(chan struct{})}
		worker := newWorkerOver(t, sweeper)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		<-sweeper.started

		worker.Deactivate()

		if !sweeper.finished.Load() {
			t.Error("deactivate returned before the tick finished")
		}
	})

	t.Run("deactivating an inactive worker does nothing", func(t *testing.T) {
		tests := []struct {
			name    string
			prepare func(t *testing.T, worker *lifecycle.Worker)
		}{
			{"never activated", func(*testing.T, *lifecycle.Worker) {}},
			{"already deactivated", func(t *testing.T, worker *lifecycle.Worker) {
				if err := worker.Activate(t.Context()); err != nil {
					t.Fatalf("Activate: %v", err)
				}
				worker.Deactivate()
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				worker, _ := newTickingWorker(t)
				tt.prepare(t, worker)

				// A panic here fails the test.
				worker.Deactivate()
			})
		}
	})

	t.Run("a deactivated worker activates again", func(t *testing.T) {
		worker, sweeper := newTickingWorker(t)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		worker.Deactivate()
		// Empty the report of any sweep from before the deactivation.
		select {
		case <-sweeper.swept:
		default:
		}

		activate(t, worker, t.Context())

		awaitSweep(t, sweeper)
	})
}

// blockingSweeper holds its first sweep until the sweep's context is done, then marks it finished.
type blockingSweeper struct {
	started  chan struct{}
	once     sync.Once
	finished atomic.Bool
}

func (s *blockingSweeper) Sweep(ctx context.Context, _ func(secret.Action)) error {
	first := false
	s.once.Do(func() {
		first = true
		close(s.started)
	})
	if first {
		<-ctx.Done()
		// Slower than a cancel, so a deactivate that does not wait returns first.
		time.Sleep(10 * time.Millisecond)
		s.finished.Store(true)
	}
	return ctx.Err()
}

// newWorkerOver returns a worker on a 1 ms interval over sweeper.
func newWorkerOver(t *testing.T, sweeper lifecycle.Sweeper) *lifecycle.Worker {
	t.Helper()
	worker, err := lifecycle.New(time.Millisecond, sweeper, &fakeRecorder{}, &fakeClock{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return worker
}

// newTickingWorker returns a worker on a 1 ms interval whose sweeper reports each sweep.
func newTickingWorker(t *testing.T) (*lifecycle.Worker, *fakeSweeper) {
	t.Helper()
	sweeper := &fakeSweeper{swept: make(chan context.Context, 1)}
	worker, err := lifecycle.New(time.Millisecond, sweeper, &fakeRecorder{}, &fakeClock{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return worker, sweeper
}

// activate activates worker on ctx and deactivates it when the test ends.
func activate(t *testing.T, worker *lifecycle.Worker, ctx context.Context) {
	t.Helper()
	if err := worker.Activate(ctx); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	t.Cleanup(worker.Deactivate)
}

// awaitSweep returns the context of the next sweep, failing if none comes within a second.
func awaitSweep(t *testing.T, sweeper *fakeSweeper) context.Context {
	t.Helper()
	select {
	case ctx := <-sweeper.swept:
		return ctx
	case <-time.After(time.Second):
		t.Fatal("got no sweep, want one")
		return nil
	}
}

// cancellableSweeper reports its actions one at a time, stopping at the first one its context is done before.
type cancellableSweeper struct {
	actions []secret.Action
}

func (s *cancellableSweeper) Sweep(ctx context.Context, report func(secret.Action)) error {
	for _, action := range s.actions {
		if err := ctx.Err(); err != nil {
			return err
		}
		report(action)
	}
	return nil
}

// cancellingRecorder keeps every event and calls cancel on each, as a deactivate arriving mid-record would.
type cancellingRecorder struct {
	fakeRecorder
	cancel context.CancelFunc
}

func (r *cancellingRecorder) Record(ctx context.Context, event audit.Event) error {
	defer r.cancel()
	return r.fakeRecorder.Record(ctx, event)
}

// failFirstRecorder fails its first record and keeps the rest.
type failFirstRecorder struct {
	fakeRecorder
	failed bool
}

func (r *failFirstRecorder) Record(ctx context.Context, event audit.Event) error {
	if !r.failed {
		r.failed = true
		return errors.New("sink failed")
	}
	return r.fakeRecorder.Record(ctx, event)
}

// eventField collects one field of each event, in order.
func eventField(events []audit.Event, field func(audit.Event) string) []string {
	got := make([]string, 0, len(events))
	for _, event := range events {
		got = append(got, field(event))
	}
	return got
}

// twoActions is one rotation and one expiry, in the order a sweep reports them.
var twoActions = []secret.Action{
	{Path: "api/key", Kind: secret.ActionRotated},
	{Path: "db/password", Kind: secret.ActionExpired},
}

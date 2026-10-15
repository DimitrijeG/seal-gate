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
)

// fakeJob reports actions and returns err from every run and counts them; ran, when set, is sent each run's context
// without blocking. Locked: the worker runs it from its own goroutine.
type fakeJob struct {
	mu      sync.Mutex
	actions []lifecycle.Action
	err     error
	calls   int
	ran     chan context.Context
}

func (j *fakeJob) Run(ctx context.Context, report func(lifecycle.Action)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls++
	select {
	case j.ran <- ctx:
	default:
	}
	for _, action := range j.actions {
		report(action)
	}
	return j.err
}

func (j *fakeJob) runs() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.calls
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
	job      *fakeJob
	recorder *fakeRecorder
	clock    *fakeClock
	log      *bytes.Buffer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{
		job:      &fakeJob{},
		recorder: &fakeRecorder{},
		clock:    &fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		log:      &bytes.Buffer{},
	}
	worker, err := lifecycle.New(time.Minute, []lifecycle.Job{f.job}, f.recorder, f.clock, slog.New(slog.NewTextHandler(f.log, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.worker = worker
	return f
}

type twoJobFixture struct {
	worker   *lifecycle.Worker
	first    *fakeJob
	second   *fakeJob
	recorder *fakeRecorder
	log      *bytes.Buffer
}

func newTwoJobFixture(t *testing.T) twoJobFixture {
	t.Helper()
	f := twoJobFixture{first: &fakeJob{}, second: &fakeJob{}, recorder: &fakeRecorder{}, log: &bytes.Buffer{}}
	worker, err := lifecycle.New(time.Minute, []lifecycle.Job{f.first, f.second}, f.recorder, &fakeClock{}, slog.New(slog.NewTextHandler(f.log, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.worker = worker
	return f
}

func TestWorker(t *testing.T) {
	t.Run("a tick runs every job", func(t *testing.T) {
		f := newTwoJobFixture(t)

		f.worker.Tick(t.Context())

		if got := []int{f.first.runs(), f.second.runs()}; !slices.Equal(got, []int{1, 1}) {
			t.Errorf("got %v runs, want [1 1]", got)
		}
	})

	t.Run("a failed job does not stop the next", func(t *testing.T) {
		f := newTwoJobFixture(t)
		f.first.err = errors.New("disk failed")

		f.worker.Tick(t.Context())

		if got := f.second.runs(); got != 1 {
			t.Errorf("got %d runs, want 1", got)
		}
	})

	t.Run("a tick's jobs share one request ID", func(t *testing.T) {
		f := newTwoJobFixture(t)
		f.first.actions = twoActions[:1]
		f.second.actions = twoActions[1:]

		f.worker.Tick(t.Context())

		if first, second := f.recorder.events[0].RequestID, f.recorder.events[1].RequestID; first != second {
			t.Errorf("got %q and %q, want one ID", first, second)
		}
	})

	t.Run("each failed job is logged", func(t *testing.T) {
		f := newTwoJobFixture(t)
		f.first.err = errors.New("disk failed")
		f.second.err = errors.New("store failed")

		f.worker.Tick(t.Context())

		for _, want := range []string{"disk failed", "store failed"} {
			if got := f.log.String(); !strings.Contains(got, want) {
				t.Errorf("got log %q, want %q", got, want)
			}
		}
	})

	t.Run("each action is audited", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions

		f.worker.Tick(t.Context())

		if got := len(f.recorder.events); got != 2 {
			t.Errorf("got %d events, want 2", got)
		}
	})

	t.Run("an event names the action's resource as its path", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions

		f.worker.Tick(t.Context())

		want := []string{"secrets/api/key", "secrets/db/password"}
		if got := eventField(f.recorder.events, func(e audit.Event) string { return e.Path }); !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an event names the action's operation as its route", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions

		f.worker.Tick(t.Context())

		want := []string{"rotate secret", "expire secret"}
		if got := eventField(f.recorder.events, func(e audit.Event) string { return e.Route }); !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an event is recorded as the lifecycle", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions[:1]

		f.worker.Tick(t.Context())

		want := audit.Event{Kind: audit.KindLifecycle, Principal: "lifecycle"}
		got := audit.Event{Kind: f.recorder.events[0].Kind, Principal: f.recorder.events[0].Principal}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("an event is stamped with the clock's time", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions[:1]

		f.worker.Tick(t.Context())

		if got := f.recorder.events[0].Time; !got.Equal(f.clock.now) {
			t.Errorf("got %v, want %v", got, f.clock.now)
		}
	})

	t.Run("a tick's events share one request ID", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions

		f.worker.Tick(t.Context())

		if first, second := f.recorder.events[0].RequestID, f.recorder.events[1].RequestID; first != second {
			t.Errorf("got %q and %q, want one ID", first, second)
		}
	})

	t.Run("two ticks have different request IDs", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions[:1]

		f.worker.Tick(t.Context())
		f.worker.Tick(t.Context())

		if first, second := f.recorder.events[0].RequestID, f.recorder.events[1].RequestID; first == "" || first == second {
			t.Errorf("got %q and %q, want two different IDs", first, second)
		}
	})

	t.Run("actions before a failed job are still audited", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions
		f.job.err = errors.New("disk failed")

		f.worker.Tick(t.Context())

		if got := len(f.recorder.events); got != 2 {
			t.Errorf("got %d events, want 2", got)
		}
	})

	t.Run("actions before a cancelled job are still audited", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		job := &cancellingJob{cancel: cancel, actions: twoActions[:1]}
		worker, err := lifecycle.New(time.Minute, []lifecycle.Job{job}, f.recorder, f.clock, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		worker.Tick(ctx)

		if got := len(f.recorder.events); got != 1 {
			t.Errorf("got %d events, want 1", got)
		}
	})

	t.Run("a cancelled tick starts no further job", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		worker, err := lifecycle.New(time.Minute, []lifecycle.Job{&cancellingJob{cancel: cancel}, f.job}, f.recorder, f.clock, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		worker.Tick(ctx)

		if got := f.job.runs(); got != 0 {
			t.Errorf("got %d runs, want 0", got)
		}
	})

	t.Run("a cancel during a record stops the job after it", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		recorder := &cancellingRecorder{cancel: cancel}
		worker, err := lifecycle.New(time.Minute, []lifecycle.Job{&cancellableJob{actions: twoActions}}, recorder, f.clock, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		worker.Tick(ctx)

		if got := len(recorder.events); got != 1 {
			t.Errorf("got %d events, want 1", got)
		}
	})

	t.Run("a failed job is logged", func(t *testing.T) {
		f := newFixture(t)
		f.job.err = errors.New("disk failed")

		f.worker.Tick(t.Context())

		if got := f.log.String(); !strings.Contains(got, "disk failed") {
			t.Errorf("got log %q, want the job's error", got)
		}
	})

	t.Run("a failed record is logged", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions[:1]
		f.recorder.err = errors.New("sink failed")

		f.worker.Tick(t.Context())

		if got := f.log.String(); !strings.Contains(got, "sink failed") {
			t.Errorf("got log %q, want the record's error", got)
		}
	})

	t.Run("a failed record does not stop the rest", func(t *testing.T) {
		f := newFixture(t)
		f.job.actions = twoActions
		recorder := &failFirstRecorder{}
		worker, err := lifecycle.New(time.Minute, []lifecycle.Job{f.job}, recorder, f.clock, slog.New(slog.NewTextHandler(f.log, nil)))
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

				_, err := lifecycle.New(tt.interval, []lifecycle.Job{f.job}, f.recorder, f.clock, slog.Default())

				if !errors.Is(err, lifecycle.ErrInvalidInterval) {
					t.Errorf("got %v, want %v", err, lifecycle.ErrInvalidInterval)
				}
			})
		}
	})

	t.Run("activate starts ticking", func(t *testing.T) {
		worker, job := newTickingWorker(t)

		activate(t, worker, t.Context())

		awaitRun(t, job)
	})

	t.Run("ticking outlives the activating context", func(t *testing.T) {
		worker, job := newTickingWorker(t)
		ctx, cancel := context.WithCancel(t.Context())
		activate(t, worker, ctx)
		cancel()
		// Drain a run that may have started before the cancel.
		awaitRun(t, job)

		if err := awaitRun(t, job).Err(); err != nil {
			t.Errorf("got %v, want a live context", err)
		}
	})

	t.Run("deactivate stops ticking", func(t *testing.T) {
		worker, job := newTickingWorker(t)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		awaitRun(t, job)

		worker.Deactivate()
		before := job.runs()
		time.Sleep(20 * time.Millisecond)

		if got := job.runs(); got != before {
			t.Errorf("got %d runs, want %d", got, before)
		}
	})

	t.Run("deactivate cancels a tick in flight", func(t *testing.T) {
		job := &blockingJob{started: make(chan struct{})}
		worker := newWorkerOver(t, job)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		<-job.started

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
		job := &blockingJob{started: make(chan struct{})}
		worker := newWorkerOver(t, job)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		<-job.started

		worker.Deactivate()

		if !job.finished.Load() {
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
		worker, job := newTickingWorker(t)
		if err := worker.Activate(t.Context()); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		worker.Deactivate()
		// Empty the report of any run from before the deactivation.
		select {
		case <-job.ran:
		default:
		}

		activate(t, worker, t.Context())

		awaitRun(t, job)
	})
}

// blockingJob holds its first run until the run's context is done, then marks it finished.
type blockingJob struct {
	started  chan struct{}
	once     sync.Once
	finished atomic.Bool
}

func (j *blockingJob) Run(ctx context.Context, _ func(lifecycle.Action)) error {
	first := false
	j.once.Do(func() {
		first = true
		close(j.started)
	})
	if first {
		<-ctx.Done()
		// Slower than a cancel, so a deactivate that does not wait returns first.
		time.Sleep(10 * time.Millisecond)
		j.finished.Store(true)
	}
	return ctx.Err()
}

// newWorkerOver returns a worker on a 1 ms interval running job.
func newWorkerOver(t *testing.T, job lifecycle.Job) *lifecycle.Worker {
	t.Helper()
	worker, err := lifecycle.New(time.Millisecond, []lifecycle.Job{job}, &fakeRecorder{}, &fakeClock{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return worker
}

// newTickingWorker returns a worker on a 1 ms interval whose job reports each run.
func newTickingWorker(t *testing.T) (*lifecycle.Worker, *fakeJob) {
	t.Helper()
	job := &fakeJob{ran: make(chan context.Context, 1)}
	return newWorkerOver(t, job), job
}

// activate activates worker on ctx and deactivates it when the test ends.
func activate(t *testing.T, worker *lifecycle.Worker, ctx context.Context) {
	t.Helper()
	if err := worker.Activate(ctx); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	t.Cleanup(worker.Deactivate)
}

// awaitRun returns the context of the job's next run, failing if none comes within a second.
func awaitRun(t *testing.T, job *fakeJob) context.Context {
	t.Helper()
	select {
	case ctx := <-job.ran:
		return ctx
	case <-time.After(time.Second):
		t.Fatal("got no run, want one")
		return nil
	}
}

// cancellingJob cancels its tick, as a deactivate arriving mid-job would, then reports its actions.
type cancellingJob struct {
	cancel  context.CancelFunc
	actions []lifecycle.Action
}

func (j *cancellingJob) Run(ctx context.Context, report func(lifecycle.Action)) error {
	j.cancel()
	for _, action := range j.actions {
		report(action)
	}
	return ctx.Err()
}

// cancellableJob reports its actions one at a time, stopping at the first one its context is done before.
type cancellableJob struct {
	actions []lifecycle.Action
}

func (j *cancellableJob) Run(ctx context.Context, report func(lifecycle.Action)) error {
	for _, action := range j.actions {
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

// twoActions is one rotation and one expiry, as the secret sweep's adapter reports them.
var twoActions = []lifecycle.Action{
	{Operation: "rotate secret", Resource: "secrets/api/key"},
	{Operation: "expire secret", Resource: "secrets/db/password"},
}

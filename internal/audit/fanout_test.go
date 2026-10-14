package audit_test

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
)

var discard = slog.New(slog.DiscardHandler)

var event = audit.Event{
	Time:      time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC),
	RequestID: "req-1",
	Kind:      audit.KindResponse,
	Principal: "root",
	Method:    "PUT",
	Route:     "PUT /v1/secrets/{path...}",
	Path:      "/v1/secrets/db/password",
	Status:    204,
}

// fakeSink records every event it is given and fails with err if set.
type fakeSink struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (f *fakeSink) Write(ctx context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return f.err
}

// hangingSink blocks until its context ends (unless ignoreContext), release is
// closed, or a safety limit passes, so a missing timeout fails a test instead of hanging it.
type hangingSink struct {
	ignoreContext bool
	release       chan struct{}
	calls         atomic.Int32
}

func newHangingSink(t *testing.T, ignoreContext bool) *hangingSink {
	t.Helper()

	sink := &hangingSink{ignoreContext: ignoreContext, release: make(chan struct{})}
	t.Cleanup(func() { close(sink.release) })
	return sink
}

func (h *hangingSink) Write(ctx context.Context, event audit.Event) error {
	h.calls.Add(1)
	done := ctx.Done()
	if h.ignoreContext {
		done = nil
	}
	select {
	case <-done:
		return ctx.Err()
	case <-h.release:
	case <-time.After(time.Second):
	}
	return nil
}

const shortTimeout = 10 * time.Millisecond

func newFanOut(t *testing.T, logger *slog.Logger, destinations ...audit.Destination) *audit.FanOut {
	t.Helper()

	fanOut, err := audit.New(logger, destinations...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fanOut
}

func TestRecord(t *testing.T) {
	t.Run("a recorded event reaches the sink", func(t *testing.T) {
		sink := &fakeSink{}
		fanOut := newFanOut(t, discard, audit.Destination{Name: "file", Sink: sink, Required: true, Timeout: time.Second})

		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Fatalf("Record: %v", err)
		}

		if want := []audit.Event{event}; !slices.Equal(sink.events, want) {
			t.Errorf("got %+v, want %+v", sink.events, want)
		}
	})

	t.Run("every sink gets the event", func(t *testing.T) {
		first, second := &fakeSink{}, &fakeSink{}
		fanOut := newFanOut(t, discard,
			audit.Destination{Name: "first", Sink: first, Required: true, Timeout: time.Second},
			audit.Destination{Name: "second", Sink: second, Required: true, Timeout: time.Second},
		)

		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Fatalf("Record: %v", err)
		}

		want := []audit.Event{event}
		if !slices.Equal(first.events, want) {
			t.Errorf("first: got %+v, want %+v", first.events, want)
		}
		if !slices.Equal(second.events, want) {
			t.Errorf("second: got %+v, want %+v", second.events, want)
		}
	})

	t.Run("a required sink's failure fails Record", func(t *testing.T) {
		failure := errors.New("disk full")
		fanOut := newFanOut(t, discard, audit.Destination{Name: "file", Sink: &fakeSink{err: failure}, Required: true, Timeout: time.Second})

		if err := fanOut.Record(t.Context(), event); !errors.Is(err, failure) {
			t.Errorf("got %v, want %v", err, failure)
		}
	})

	t.Run("an optional sink's failure does not fail Record", func(t *testing.T) {
		fanOut := newFanOut(t, discard, audit.Destination{Name: "feed", Sink: &fakeSink{err: errors.New("unreachable")}, Timeout: time.Second})

		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("an optional sink's failure is logged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		fanOut := newFanOut(t, logger, audit.Destination{Name: "feed", Sink: &fakeSink{err: errors.New("unreachable")}, Timeout: time.Second})

		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Fatalf("Record: %v", err)
		}

		if !strings.Contains(buf.String(), "feed") {
			t.Errorf("got %q, want the sink's name", buf.String())
		}
	})

	t.Run("a logged failure leaves the event out", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		fanOut := newFanOut(t, logger, audit.Destination{Name: "feed", Sink: &fakeSink{err: errors.New("unreachable")}, Timeout: time.Second})

		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Fatalf("Record: %v", err)
		}

		if strings.Contains(buf.String(), event.Path) {
			t.Errorf("got %q, want no %q", buf.String(), event.Path)
		}
	})

	t.Run("a failed sink does not stop the next", func(t *testing.T) {
		next := &fakeSink{}
		fanOut := newFanOut(t, discard,
			audit.Destination{Name: "file", Sink: &fakeSink{err: errors.New("disk full")}, Required: true, Timeout: time.Second},
			audit.Destination{Name: "feed", Sink: next, Timeout: time.Second},
		)

		_ = fanOut.Record(t.Context(), event)

		if want := []audit.Event{event}; !slices.Equal(next.events, want) {
			t.Errorf("got %+v, want %+v", next.events, want)
		}
	})

	t.Run("every required failure is reported", func(t *testing.T) {
		full, gone := errors.New("disk full"), errors.New("connection reset")
		fanOut := newFanOut(t, discard,
			audit.Destination{Name: "file", Sink: &fakeSink{err: full}, Required: true, Timeout: time.Second},
			audit.Destination{Name: "remote", Sink: &fakeSink{err: gone}, Required: true, Timeout: time.Second},
		)

		err := fanOut.Record(t.Context(), event)

		for _, want := range []error{full, gone} {
			if !errors.Is(err, want) {
				t.Errorf("got %v, want %v", err, want)
			}
		}
	})
}

func TestTimeout(t *testing.T) {
	t.Run("a required sink that hangs fails Record", func(t *testing.T) {
		fanOut := newFanOut(t, discard, audit.Destination{Name: "file", Sink: newHangingSink(t, false), Required: true, Timeout: shortTimeout})

		if err := fanOut.Record(t.Context(), event); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("got %v, want %v", err, context.DeadlineExceeded)
		}
	})

	t.Run("a sink that ignores its context still times out", func(t *testing.T) {
		fanOut := newFanOut(t, discard, audit.Destination{Name: "file", Sink: newHangingSink(t, true), Required: true, Timeout: shortTimeout})

		if err := fanOut.Record(t.Context(), event); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("got %v, want %v", err, context.DeadlineExceeded)
		}
	})

	t.Run("an optional sink that hangs does not fail Record", func(t *testing.T) {
		fanOut := newFanOut(t, discard, audit.Destination{Name: "feed", Sink: newHangingSink(t, false), Timeout: shortTimeout})

		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a hung sink does not spend the next sink's time", func(t *testing.T) {
		next := &fakeSink{}
		fanOut := newFanOut(t, discard,
			audit.Destination{Name: "feed", Sink: newHangingSink(t, false), Timeout: shortTimeout},
			audit.Destination{Name: "file", Sink: expiredCheck{next}, Required: true, Timeout: shortTimeout},
		)

		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Fatalf("Record: %v", err)
		}

		if want := []audit.Event{event}; !slices.Equal(next.events, want) {
			t.Errorf("got %+v, want %+v", next.events, want)
		}
	})

	t.Run("a sink still stuck in a write is not given another", func(t *testing.T) {
		sink := newHangingSink(t, true)
		fanOut := newFanOut(t, discard, audit.Destination{Name: "file", Sink: sink, Required: true, Timeout: shortTimeout})

		_ = fanOut.Record(t.Context(), event)
		if err := fanOut.Record(t.Context(), event); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Record: got %v, want %v", err, context.DeadlineExceeded)
		}

		if got := sink.calls.Load(); got != 1 {
			t.Errorf("calls: got %d, want 1", got)
		}
	})

	t.Run("concurrent records to a healthy sink all succeed", func(t *testing.T) {
		const records = 20
		sink := &fakeSink{}
		fanOut := newFanOut(t, discard, audit.Destination{Name: "file", Sink: sink, Required: true, Timeout: time.Second})

		errs := make(chan error, records)
		var wg sync.WaitGroup
		for range records {
			wg.Go(func() { errs <- fanOut.Record(t.Context(), event) })
		}
		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				t.Errorf("got %v, want nil", err)
			}
		}
		if got := len(sink.events); got != records {
			t.Errorf("events: got %d, want %d", got, records)
		}
	})
}

// expiredCheck fails a write whose context is already done, so a deadline
// spent before the write began shows.
type expiredCheck struct {
	sink *fakeSink
}

func (e expiredCheck) Write(ctx context.Context, event audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.sink.Write(ctx, event)
}

func TestNew(t *testing.T) {
	t.Run("a recorder with no sinks cannot be built", func(t *testing.T) {
		if _, err := audit.New(discard); !errors.Is(err, audit.ErrNoSinks) {
			t.Errorf("got %v, want %v", err, audit.ErrNoSinks)
		}
	})

	t.Run("the recorder keeps its own copy of the destinations", func(t *testing.T) {
		original := &fakeSink{}
		destinations := []audit.Destination{{Name: "file", Sink: original, Required: true, Timeout: time.Second}}
		fanOut := newFanOut(t, discard, destinations...)

		destinations[0].Sink = &fakeSink{}
		if err := fanOut.Record(t.Context(), event); err != nil {
			t.Fatalf("Record: %v", err)
		}

		if want := []audit.Event{event}; !slices.Equal(original.events, want) {
			t.Errorf("got %+v, want %+v", original.events, want)
		}
	})

	t.Run("a destination without a positive timeout is refused", func(t *testing.T) {
		cases := []struct {
			name    string
			timeout time.Duration
		}{
			{"zero", 0},
			{"negative", -time.Second},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := audit.New(discard, audit.Destination{Name: "file", Sink: &fakeSink{}, Required: true, Timeout: tc.timeout})
				if !errors.Is(err, audit.ErrInvalidTimeout) {
					t.Errorf("got %v, want %v", err, audit.ErrInvalidTimeout)
				}
			})
		}
	})

	t.Run("a destination without a sink is refused", func(t *testing.T) {
		_, err := audit.New(discard, audit.Destination{Name: "file", Required: true, Timeout: time.Second})
		if !errors.Is(err, audit.ErrNilSink) {
			t.Errorf("got %v, want %v", err, audit.ErrNilSink)
		}
	})
}

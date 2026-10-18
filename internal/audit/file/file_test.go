package file_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/audit/file"
)

// lineBody mirrors the file's line format, so a renamed key fails a test.
type lineBody struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id"`
	Kind      string    `json:"kind"`
	Principal string    `json:"principal"`
	Method    string    `json:"method"`
	Route     string    `json:"route"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
}

func TestWrite(t *testing.T) {
	t.Run("an event is written as one JSON line", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		event := audit.Event{
			Time:      time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC),
			RequestID: "req-1",
			Kind:      audit.KindResponse,
			Principal: "root",
			Method:    "PUT",
			Route:     "PUT /v1/secrets/{path...}",
			Path:      "/v1/secrets/db",
			Status:    204,
		}

		write(t, newSink(t, path), event)

		var got lineBody
		decodeOnlyLine(t, path, &got)
		want := lineBody{
			Time:      event.Time,
			RequestID: "req-1",
			Kind:      "response",
			Principal: "root",
			Method:    "PUT",
			Route:     "PUT /v1/secrets/{path...}",
			Path:      "/v1/secrets/db",
			Status:    204,
		}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the time is written in UTC", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		zone := time.FixedZone("UTC+2", 2*60*60)
		event := audit.Event{Time: time.Date(2026, 10, 14, 14, 0, 0, 0, zone), Kind: audit.KindRequest}

		write(t, newSink(t, path), event)

		var got struct {
			Time string `json:"time"`
		}
		decodeOnlyLine(t, path, &got)
		if want := "2026-10-14T12:00:00Z"; got.Time != want {
			t.Errorf("got %q, want %q", got.Time, want)
		}
	})

	t.Run("a request event has no status", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")

		write(t, newSink(t, path), audit.Event{Kind: audit.KindRequest})

		var got map[string]any
		decodeOnlyLine(t, path, &got)
		if status, ok := got["status"]; ok {
			t.Errorf("got status %v, want none", status)
		}
	})

	t.Run("each event is its own line", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		sink := newSink(t, path)

		write(t, sink, audit.Event{RequestID: "first"})
		write(t, sink, audit.Event{RequestID: "second"})

		assertRequestIDs(t, path, "first", "second")
	})

	t.Run("a reopened file is appended to, not overwritten", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		first := newSink(t, path)
		write(t, first, audit.Event{RequestID: "before"})
		if err := first.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		write(t, newSink(t, path), audit.Event{RequestID: "after"})

		assertRequestIDs(t, path, "before", "after")
	})

	t.Run("concurrent writes leave whole lines", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		sink := newSink(t, path)
		const writers = 50

		var wg sync.WaitGroup
		errs := make(chan error, writers)
		for i := range writers {
			wg.Go(func() {
				errs <- sink.Write(t.Context(), audit.Event{RequestID: strconv.Itoa(i)})
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
		}

		got := requestIDs(t, path)
		want := make([]string, writers)
		for i := range want {
			want[i] = strconv.Itoa(i)
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an event that cannot be encoded writes nothing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		// encoding/json refuses years past 9999.
		event := audit.Event{Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Kind: audit.KindRequest}

		err := newSink(t, path).Write(t.Context(), event)
		var marshalErr *json.MarshalerError
		if !errors.As(err, &marshalErr) {
			t.Fatalf("got %v, want a %T", err, marshalErr)
		}
		if lines := readLines(t, path); len(lines) != 0 {
			t.Errorf("got %d lines, want 0", len(lines))
		}
	})

	t.Run("a write after close fails", func(t *testing.T) {
		sink := newSink(t, filepath.Join(t.TempDir(), "audit.log"))
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		err := sink.Write(t.Context(), audit.Event{Kind: audit.KindRequest})
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("got %v, want %v", err, os.ErrClosed)
		}
	})
}

func TestNew(t *testing.T) {
	t.Run("a new file is readable by its owner only", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows has no Unix permission bits")
		}
		path := filepath.Join(t.TempDir(), "audit.log")
		newSink(t, path)

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if got, want := info.Mode().Perm(), fs.FileMode(0o600); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a path in a missing directory is refused", func(t *testing.T) {
		_, err := file.New(filepath.Join(t.TempDir(), "missing", "audit.log"), true)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("got %v, want %v", err, fs.ErrNotExist)
		}
	})
}

func TestClose(t *testing.T) {
	t.Run("a second close reports the file closed", func(t *testing.T) {
		sink := newSink(t, filepath.Join(t.TempDir(), "audit.log"))
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		if err := sink.Close(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("got %v, want %v", err, os.ErrClosed)
		}
	})
}

// newSink closes the sink on cleanup; closing it earlier is harmless.
func newSink(t *testing.T, path string) *file.Sink {
	t.Helper()
	s, err := file.New(path, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func write(t *testing.T, sink audit.Sink, event audit.Event) {
	t.Helper()
	if err := sink.Write(t.Context(), event); err != nil {
		t.Fatalf("Write: %v", err)
	}
}

// decodeOnlyLine fails unless the file holds exactly one line.
func decodeOnlyLine(t *testing.T, path string, v any) {
	t.Helper()
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	if err := json.Unmarshal(lines[0], v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
}

func assertRequestIDs(t *testing.T, path string, want ...string) {
	t.Helper()
	if got := requestIDs(t, path); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// requestIDs decodes every line, so a torn or merged line fails here.
func requestIDs(t *testing.T, path string) []string {
	t.Helper()
	var ids []string
	for _, l := range readLines(t, path) {
		var body lineBody
		if err := json.Unmarshal(l, &body); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		ids = append(ids, body.RequestID)
	}
	return ids
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, append([]byte(nil), scanner.Bytes()...))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return lines
}

package httpapi_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
)

var (
	start   = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	errDisk = errors.New("disk on fire")
)

// withoutTiming clears the fields that vary per request, so the rest compares as a whole.
func withoutTiming(event audit.Event) audit.Event {
	event.Time = time.Time{}
	event.RequestID = ""
	return event
}

// recordStatus sends one status request through h, whose Auditor must be auditor, and returns at least want events.
func recordStatus(t *testing.T, h *httpapi.Handlers, auditor *fakeAuditor, want int) []audit.Event {
	t.Helper()
	do(t, newRouter(h), http.MethodGet, "/v1/sys/status", "")
	if len(auditor.events) < want {
		t.Fatalf("got %d events, want %d", len(auditor.events), want)
	}
	return auditor.events
}

func TestAudit(t *testing.T) {
	t.Run("a request is recorded as a request event", func(t *testing.T) {
		auditor := &fakeAuditor{}
		want := audit.Event{Kind: audit.KindRequest, Method: http.MethodGet, Route: "GET /v1/sys/status", Path: "/v1/sys/status"}

		events := recordStatus(t, &httpapi.Handlers{Auditor: auditor, System: &fakeSystem{}}, auditor, 1)

		if got := withoutTiming(events[0]); got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the request event is stamped by the clock", func(t *testing.T) {
		auditor := &fakeAuditor{}

		events := recordStatus(t, &httpapi.Handlers{Auditor: auditor, Clock: &fakeClock{next: start}, System: &fakeSystem{}}, auditor, 1)

		if got := events[0].Time; !got.Equal(start) {
			t.Errorf("got %v, want %v", got, start)
		}
	})

	t.Run("the response is recorded with its status", func(t *testing.T) {
		auditor := &fakeAuditor{}
		want := audit.Event{Kind: audit.KindResponse, Method: http.MethodGet, Route: "GET /v1/sys/status", Path: "/v1/sys/status", Status: http.StatusOK}

		events := recordStatus(t, &httpapi.Handlers{Auditor: auditor, System: &fakeSystem{}}, auditor, 2)

		if got := withoutTiming(events[1]); got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a failed response is recorded with its error status", func(t *testing.T) {
		auditor := &fakeAuditor{}

		events := recordStatus(t, &httpapi.Handlers{Auditor: auditor, System: &fakeSystem{statusErr: errDisk}}, auditor, 2)

		if got := events[1].Status; got != http.StatusInternalServerError {
			t.Errorf("got %d, want %d", got, http.StatusInternalServerError)
		}
	})

	t.Run("the response event is stamped after the handler", func(t *testing.T) {
		auditor := &fakeAuditor{}
		// The fake clock moves on a second per reading, so a second reading is start plus one second.
		want := start.Add(time.Second)

		events := recordStatus(t, &httpapi.Handlers{Auditor: auditor, Clock: &fakeClock{next: start}, System: &fakeSystem{}}, auditor, 2)

		if got := events[1].Time; !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("both events share a request ID", func(t *testing.T) {
		auditor := &fakeAuditor{}

		events := recordStatus(t, &httpapi.Handlers{Auditor: auditor, System: &fakeSystem{}}, auditor, 2)
		want := events[0].RequestID
		if want == "" {
			t.Fatalf("got an empty request ID, want one")
		}

		if got := events[1].RequestID; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("two requests get different request IDs", func(t *testing.T) {
		auditor := &fakeAuditor{}
		h := &httpapi.Handlers{Auditor: auditor, System: &fakeSystem{}}

		recordStatus(t, h, auditor, 2)
		events := recordStatus(t, h, auditor, 4)

		if first, second := events[0].RequestID, events[2].RequestID; first == second {
			t.Errorf("got %q twice, want two IDs", first)
		}
	})

	t.Run("a request that cannot be recorded never runs", func(t *testing.T) {
		auditor := &fakeAuditor{errs: map[audit.Kind]error{audit.KindRequest: errDisk}}
		system := &fakeSystem{}

		recordStatus(t, &httpapi.Handlers{Auditor: auditor, System: system}, auditor, 1)

		if system.statusCalls != 0 {
			t.Errorf("got %d status calls, want 0", system.statusCalls)
		}
	})

	t.Run("a request that cannot be recorded gets a generic 500", func(t *testing.T) {
		auditor := &fakeAuditor{errs: map[audit.Kind]error{audit.KindRequest: errDisk}}
		router := newRouter(&httpapi.Handlers{Auditor: auditor, System: &fakeSystem{}})

		rec := do(t, router, http.MethodGet, "/v1/sys/status", "")

		assertError(t, rec, http.StatusInternalServerError, "internal error")
	})

	t.Run("a failed response record is logged", func(t *testing.T) {
		auditor := &fakeAuditor{errs: map[audit.Kind]error{audit.KindResponse: errDisk}}
		var log bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&log, nil))

		recordStatus(t, &httpapi.Handlers{Auditor: auditor, System: &fakeSystem{}, Logger: logger}, auditor, 2)

		if !strings.Contains(log.String(), errDisk.Error()) {
			t.Errorf("got log %q, want it to hold %q", log.String(), errDisk)
		}
	})
}

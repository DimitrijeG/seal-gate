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
	"github.com/dimitrijegasic/seal-gate/internal/authorization"
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

// record sends one request through h, whose Auditor must be auditor, and returns at least want events.
func record(t *testing.T, h *httpapi.Handlers, auditor *fakeAuditor, authorization, method, path string, want int) []audit.Event {
	t.Helper()
	doWithAuthorization(t, newRouter(h), authorization, method, path, "")
	if len(auditor.events) < want {
		t.Fatalf("got %d events, want %d", len(auditor.events), want)
	}
	return auditor.events
}

// recordStatus is record for one status request.
func recordStatus(t *testing.T, h *httpapi.Handlers, auditor *fakeAuditor, want int) []audit.Event {
	t.Helper()
	return record(t, h, auditor, bearer, http.MethodGet, "/v1/sys/status", want)
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

	t.Run("an authenticated request is recorded with its principal", func(t *testing.T) {
		auditor := &fakeAuditor{}
		h := &httpapi.Handlers{
			Auditor:       auditor,
			Authenticator: &fakeAuthenticator{principal: authorization.NewEntityPrincipal(entityID)},
			Secret:        &fakeSecret{},
		}

		events := record(t, h, auditor, bearer, http.MethodGet, "/v1/secrets/db/password", 1)

		if got := events[0].Principal; got != entityID {
			t.Errorf("got %q, want %q", got, entityID)
		}
	})

	t.Run("a request without a token is recorded with its 401", func(t *testing.T) {
		auditor := &fakeAuditor{}
		h := &httpapi.Handlers{Auditor: auditor, Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{}}

		events := record(t, h, auditor, "", http.MethodGet, "/v1/secrets/db/password", 2)

		if got := events[1].Status; got != http.StatusUnauthorized {
			t.Errorf("got %d, want %d", got, http.StatusUnauthorized)
		}
	})

	t.Run("a denied request is recorded with its 403", func(t *testing.T) {
		auditor := &fakeAuditor{}
		h := &httpapi.Handlers{Auditor: auditor, Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{err: authorization.ErrDenied}}

		events := record(t, h, auditor, bearer, http.MethodGet, "/v1/secrets/db/password", 2)

		if got := events[1].Status; got != http.StatusForbidden {
			t.Errorf("got %d, want %d", got, http.StatusForbidden)
		}
	})

	t.Run("every route is audited", func(t *testing.T) {
		// Every pattern NewRouter registers; a route missing here goes unchecked.
		tests := []struct{ route, path string }{
			{"POST /v1/sys/init", "/v1/sys/init"},
			{"POST /v1/sys/unseal", "/v1/sys/unseal"},
			{"GET /v1/sys/status", "/v1/sys/status"},
			{"GET /v1/sys/health", "/v1/sys/health"},
			{"POST /v1/sys/seal", "/v1/sys/seal"},
			{"POST /v1/auth/token/revoke", "/v1/auth/token/revoke"},
			{"POST /v1/auth/token/rotate", "/v1/auth/token/rotate"},
			{"PUT /v1/auth/users/{name}", "/v1/auth/users/alice"},
			{"DELETE /v1/auth/users/{name}", "/v1/auth/users/alice"},
			{"GET /v1/secrets", "/v1/secrets"},
			{"PUT /v1/secrets/{path...}", "/v1/secrets/db/password"},
			{"GET /v1/secrets/{path...}", "/v1/secrets/db/password"},
			{"DELETE /v1/secrets/{path...}", "/v1/secrets/db/password"},
			{"POST /v1/secrets/generate/{path...}", "/v1/secrets/generate/db/password"},
			{"POST /v1/secrets/rotate/{path...}", "/v1/secrets/rotate/db/password"},
			{"PUT /v1/policies/{name}", "/v1/policies/dev"},
			{"GET /v1/policies/{name}", "/v1/policies/dev"},
			{"DELETE /v1/policies/{name}", "/v1/policies/dev"},
			{"POST /v1/entities", "/v1/entities"},
			{"GET /v1/entities/{id}", "/v1/entities/" + entityID},
			{"PUT /v1/entities/{id}", "/v1/entities/" + entityID},
			{"DELETE /v1/entities/{id}", "/v1/entities/" + entityID},
			{"POST /v1/entities/{id}/tokens", "/v1/entities/" + entityID + "/tokens"},
			{"POST /v1/groups", "/v1/groups"},
			{"GET /v1/groups/{id}", "/v1/groups/" + groupID},
			{"PUT /v1/groups/{id}", "/v1/groups/" + groupID},
			{"DELETE /v1/groups/{id}", "/v1/groups/" + groupID},
		}

		for _, tt := range tests {
			t.Run(tt.route, func(t *testing.T) {
				auditor := &fakeAuditor{}
				h := &httpapi.Handlers{
					Auditor:       auditor,
					Authenticator: &fakeAuthenticator{},
					System:        &fakeSystem{},
					Secret:        &fakeSecret{},
					Policy:        &fakePolicy{},
					Entity:        &fakeEntity{},
					Token:         &fakeToken{},
					Group:         &fakeGroup{},
					User:          &fakeUser{},
				}
				method, _, _ := strings.Cut(tt.route, " ")

				events := record(t, h, auditor, bearer, method, tt.path, 1)

				if got := events[0].Route; got != tt.route {
					t.Errorf("got %q, want %q", got, tt.route)
				}
			})
		}
	})
}

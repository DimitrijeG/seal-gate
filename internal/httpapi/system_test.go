package httpapi_test

import (
	"bytes"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

func TestInit(t *testing.T) {
	t.Run("init returns the shares as base64", func(t *testing.T) {
		fake := &fakeSystem{initResult: system.InitResult{Shares: [][]byte{{1, 2}, {3, 4}}}}
		router := newRouter(&httpapi.Handlers{System: fake})
		want := []string{"AQI=", "AwQ="}

		rec := do(t, router, http.MethodPost, "/v1/sys/init", `{"shares":2,"threshold":2}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[initBody](t, rec)

		if !slices.Equal(got.Shares, want) {
			t.Errorf("got %v, want %v", got.Shares, want)
		}
	})

	t.Run("init returns the root token as base64", func(t *testing.T) {
		fake := &fakeSystem{initResult: system.InitResult{RootToken: []byte{5, 6}}}
		router := newRouter(&httpapi.Handlers{System: fake})
		want := "BQY="

		rec := do(t, router, http.MethodPost, "/v1/sys/init", `{"shares":2,"threshold":2}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[initBody](t, rec)

		if got.RootToken != want {
			t.Errorf("got %q, want %q", got.RootToken, want)
		}
	})

	t.Run("init passes the requested configuration to the service", func(t *testing.T) {
		fake := &fakeSystem{}
		router := newRouter(&httpapi.Handlers{System: fake})
		want := system.SealConfiguration{Shares: 5, Threshold: 3}

		rec := do(t, router, http.MethodPost, "/v1/sys/init", `{"shares":5,"threshold":3}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if fake.initConfig != want {
			t.Errorf("got %+v, want %+v", fake.initConfig, want)
		}
	})

	t.Run("init maps service errors to statuses", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"invalid config", system.ErrInvalidSealConfig, http.StatusBadRequest, "invalid seal configuration"},
			{"already initialized", system.ErrAlreadyInitialized, http.StatusConflict, "already initialized"},
			{"unknown error", errors.New("bolt: data.db: permission denied"), http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{System: &fakeSystem{initErr: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/sys/init", `{"shares":2,"threshold":2}`)

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("init clears the shares once they are written", func(t *testing.T) {
		shares := [][]byte{{1, 2}, {3, 4}}
		fake := &fakeSystem{initResult: system.InitResult{Shares: shares}}
		router := newRouter(&httpapi.Handlers{System: fake})

		rec := do(t, router, http.MethodPost, "/v1/sys/init", `{"shares":2,"threshold":2}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		for i, s := range shares {
			if !bytes.Equal(s, make([]byte, len(s))) {
				t.Errorf("shares[%d] = %x, want zeros", i, s)
			}
		}
	})

	t.Run("init clears the root token once it is written", func(t *testing.T) {
		token := []byte{5, 6}
		fake := &fakeSystem{initResult: system.InitResult{RootToken: token}}
		router := newRouter(&httpapi.Handlers{System: fake})

		rec := do(t, router, http.MethodPost, "/v1/sys/init", `{"shares":2,"threshold":2}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if !bytes.Equal(token, make([]byte, len(token))) {
			t.Errorf("got %x, want zeros", token)
		}
	})
}

func TestUnseal(t *testing.T) {
	t.Run("unseal passes the decoded share to the service", func(t *testing.T) {
		fake := &fakeSystem{}
		router := newRouter(&httpapi.Handlers{System: fake})

		rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"AQI="}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if !bytes.Equal(fake.unsealShare, []byte{1, 2}) {
			t.Errorf("got %x, want %x", fake.unsealShare, []byte{1, 2})
		}
	})

	t.Run("unseal returns the service's status", func(t *testing.T) {
		status := system.Status{Initialized: true, Sealed: true, Config: system.SealConfiguration{Shares: 5, Threshold: 3}, Progress: 2}
		fake := &fakeSystem{unsealResult: status}
		router := newRouter(&httpapi.Handlers{System: fake})
		want := statusBody{
			Initialized: true,
			Sealed:      true,
			Shares:      5,
			Threshold:   3,
			Progress:    2,
		}

		rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"AQI="}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[statusBody](t, rec)

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("unseal maps service errors to statuses", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"not initialized", system.ErrNotInitialized, http.StatusConflict, "not initialized"},
			{"already unsealed", system.ErrAlreadyUnsealed, http.StatusConflict, "already unsealed"},
			{"invalid share", system.ErrInvalidShare, http.StatusBadRequest, "invalid unseal share"},
			{"duplicate share", system.ErrDuplicateShare, http.StatusConflict, "share already submitted"},
			{"unknown error", errors.New("bolt: data.db: permission denied"), http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{System: &fakeSystem{unsealErr: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"AQI="}`)

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("unseal rejects a share that is not base64", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{System: &fakeSystem{}})

		rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"!!"}`)

		assertError(t, rec, http.StatusBadRequest, "request body has a value that is not valid base64")
	})

	t.Run("unseal clears the decoded share after the call", func(t *testing.T) {
		tests := []struct {
			name   string
			err    error
			status int
		}{
			{"service succeeds", nil, http.StatusOK},
			{"service fails", system.ErrInvalidShare, http.StatusBadRequest},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeSystem{unsealErr: tt.err}
				router := newRouter(&httpapi.Handlers{System: fake})
				// A fixed length, so a service never called (nil) cannot pass as cleared.
				want := []byte{0, 0}

				rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"AQI="}`)
				if rec.Code != tt.status {
					t.Fatalf("status: got %d, want %d: %s", rec.Code, tt.status, rec.Body)
				}

				if !bytes.Equal(fake.unsealGiven, want) {
					t.Errorf("got %x, want %x", fake.unsealGiven, want)
				}
			})
		}
	})

	t.Run("a reset returns the service's status", func(t *testing.T) {
		fake := &fakeSystem{
			// Unseal's status differs, so a handler that submits a share cannot pass.
			unsealResult: system.Status{Initialized: true, Sealed: true, Progress: 2},
			resetResult:  system.Status{Initialized: true, Sealed: true, Config: system.SealConfiguration{Shares: 5, Threshold: 3}},
		}
		router := newRouter(&httpapi.Handlers{System: fake})
		want := statusBody{Initialized: true, Sealed: true, Shares: 5, Threshold: 3, Progress: 0}

		rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"reset":true}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[statusBody](t, rec)

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a reset maps service errors to statuses", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"already unsealed", system.ErrAlreadyUnsealed, http.StatusConflict, "already unsealed"},
			{"not initialized", system.ErrNotInitialized, http.StatusConflict, "not initialized"},
			{"unknown error", errors.New("bolt: data.db: permission denied"), http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{System: &fakeSystem{resetErr: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"reset":true}`)

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("a share and a reset together are rejected", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{System: &fakeSystem{}})

		rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"AQI=","reset":true}`)

		assertError(t, rec, http.StatusBadRequest, "share and reset cannot be sent together")
	})

	t.Run("a reset with an empty share is a reset", func(t *testing.T) {
		fake := &fakeSystem{resetResult: system.Status{Initialized: true, Sealed: true}}
		router := newRouter(&httpapi.Handlers{System: fake})
		want := statusBody{Initialized: true, Sealed: true}

		rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"","reset":true}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[statusBody](t, rec)

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
}

func TestSeal(t *testing.T) {
	t.Run("seal returns 204 with no body", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, System: &fakeSystem{}})

		rec := do(t, router, http.MethodPost, "/v1/sys/seal", "")

		if rec.Code != http.StatusNoContent {
			t.Errorf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("body: got %q, want empty", rec.Body)
		}
		if rec.Header().Get("Content-Type") != "" {
			t.Errorf("Content-Type: got %q, want empty", rec.Header().Get("Content-Type"))
		}
	})

	t.Run("seal seals the service", func(t *testing.T) {
		fake := &fakeSystem{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, System: fake})

		rec := do(t, router, http.MethodPost, "/v1/sys/seal", "")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !fake.sealed {
			t.Error("service is not sealed")
		}
	})

	t.Run("seal passes the authenticated principal to the service", func(t *testing.T) {
		fake := &fakeSystem{}
		want := authorization.NewEntityPrincipal(entityID, "ops")
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{principal: want}, System: fake})

		do(t, router, http.MethodPost, "/v1/sys/seal", "")

		if !reflect.DeepEqual(fake.principal, want) {
			t.Errorf("got %+v, want %+v", fake.principal, want)
		}
	})

	t.Run("a denied seal is forbidden", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, System: &fakeSystem{sealErr: authorization.ErrDenied}})

		rec := do(t, router, http.MethodPost, "/v1/sys/seal", "")

		assertError(t, rec, http.StatusForbidden, "permission denied")
	})
}

func TestStatus(t *testing.T) {
	t.Run("status reports the service's state", func(t *testing.T) {
		status := system.Status{Initialized: true, Sealed: true, Config: system.SealConfiguration{Shares: 5, Threshold: 3}, Progress: 2}
		router := newRouter(&httpapi.Handlers{System: &fakeSystem{statusResult: status}})
		want := statusBody{Initialized: true, Sealed: true, Shares: 5, Threshold: 3, Progress: 2}

		rec := do(t, router, http.MethodGet, "/v1/sys/status", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[statusBody](t, rec)

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("status before init omits shares and threshold", func(t *testing.T) {
		status := system.Status{Sealed: true}
		router := newRouter(&httpapi.Handlers{System: &fakeSystem{statusResult: status}})

		rec := do(t, router, http.MethodGet, "/v1/sys/status", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		// A map, not statusBody: a struct cannot tell an absent key from a zero.
		got := decode[map[string]any](t, rec)

		for _, key := range []string{"shares", "threshold"} {
			if v, ok := got[key]; ok {
				t.Errorf("%s: got %v, want absent", key, v)
			}
		}
	})

	t.Run("status hides a service failure behind a generic 500", func(t *testing.T) {
		fake := &fakeSystem{statusErr: errors.New("bolt: data.db: permission denied")}
		router := newRouter(&httpapi.Handlers{System: fake})

		rec := do(t, router, http.MethodGet, "/v1/sys/status", "")

		assertError(t, rec, http.StatusInternalServerError, "internal error")
	})
}

func TestHealth(t *testing.T) {
	t.Run("health is 204 when unsealed", func(t *testing.T) {
		status := system.Status{Sealed: false}
		router := newRouter(&httpapi.Handlers{System: &fakeSystem{statusResult: status}})

		rec := do(t, router, http.MethodGet, "/v1/sys/health", "")
		if rec.Code != http.StatusNoContent {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
	})

	t.Run("health is 503 when not unsealed", func(t *testing.T) {
		tests := []struct {
			name   string
			status system.Status
		}{
			{"sealed", system.Status{Initialized: true, Sealed: true}},
			{"uninitialized", system.Status{Sealed: true}},
		}

		want := "the system is sealed"
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{System: &fakeSystem{statusResult: tt.status}})

				rec := do(t, router, http.MethodGet, "/v1/sys/health", "")

				assertError(t, rec, http.StatusServiceUnavailable, want)
			})
		}
	})

	t.Run("health hides a service failure behind a generic 500", func(t *testing.T) {
		fake := &fakeSystem{statusErr: errors.New("bolt: data.db: permission denied")}
		router := newRouter(&httpapi.Handlers{System: fake})

		rec := do(t, router, http.MethodGet, "/v1/sys/health", "")

		assertError(t, rec, http.StatusInternalServerError, "internal error")
	})
}

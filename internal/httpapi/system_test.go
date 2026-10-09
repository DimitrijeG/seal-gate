package httpapi_test

import (
	"bytes"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

func TestInit(t *testing.T) {
	t.Run("init returns the shares as base64", func(t *testing.T) {
		fake := &fakeSystem{initResult: system.InitResult{Shares: [][]byte{{1, 2}, {3, 4}}}}
		router := httpapi.NewRouter(&httpapi.Handlers{System: fake})
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

	t.Run("init passes the requested configuration to the service", func(t *testing.T) {
		fake := &fakeSystem{}
		router := httpapi.NewRouter(&httpapi.Handlers{System: fake})
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
				router := httpapi.NewRouter(&httpapi.Handlers{System: &fakeSystem{initErr: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/sys/init", `{"shares":2,"threshold":2}`)

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("init clears the shares once they are written", func(t *testing.T) {
		shares := [][]byte{{1, 2}, {3, 4}}
		fake := &fakeSystem{initResult: system.InitResult{Shares: shares}}
		router := httpapi.NewRouter(&httpapi.Handlers{System: fake})

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
}

func TestUnseal(t *testing.T) {
	t.Run("unseal passes the decoded share to the service", func(t *testing.T) {
		fake := &fakeSystem{}
		router := httpapi.NewRouter(&httpapi.Handlers{System: fake})

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
		router := httpapi.NewRouter(&httpapi.Handlers{System: fake})
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
			{"unknown error", errors.New("bolt: data.db: permission denied"), http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{System: &fakeSystem{unsealErr: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/sys/unseal", `{"share":"AQI="}`)

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("unseal rejects a share that is not base64", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{System: &fakeSystem{}})

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
				router := httpapi.NewRouter(&httpapi.Handlers{System: fake})
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
}

func TestSeal(t *testing.T) {
	t.Run("seal returns 204 with no body", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{System: &fakeSystem{}})

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
		router := httpapi.NewRouter(&httpapi.Handlers{System: fake})

		rec := do(t, router, http.MethodPost, "/v1/sys/seal", "")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !fake.sealed {
			t.Error("service is not sealed")
		}
	})
}

package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

type statusBody struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Shares      int  `json:"shares"`
	Threshold   int  `json:"threshold"`
	Progress    int  `json:"progress"`
}

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

// newRouter wires the real components over a fresh memory backend.
func newRouter(t *testing.T) http.Handler {
	t.Helper()
	infra, err := buildInfrastructure(&config.Config{
		Logger: config.LoggerConfig{Level: "error", Format: "text"},
		Crypto: config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
	})
	if err != nil {
		t.Fatalf("buildInfrastructure: %v", err)
	}
	infra.clock = fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	services := buildServices(infra, buildRepositories(memory.New(), infra))
	return httpapi.NewRouter(&httpapi.Handlers{System: services.system, Logger: infra.logger})
}

func send(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return v
}

// initialize makes a 3-of-5 instance and returns its shares.
func initialize(t *testing.T, h http.Handler) []string {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/sys/init", `{"shares":5,"threshold":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("init: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
	}
	return decode[struct {
		Shares []string `json:"shares"`
	}](t, rec).Shares
}

func unseal(t *testing.T, h http.Handler, share string) statusBody {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/sys/unseal", fmt.Sprintf(`{"share":%q}`, share))
	if rec.Code != http.StatusOK {
		t.Fatalf("unseal: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
	}
	return decode[statusBody](t, rec)
}

func TestSealLifecycle(t *testing.T) {
	t.Run("init leaves the instance sealed", func(t *testing.T) {
		router := newRouter(t)
		initialize(t, router)
		want := statusBody{Initialized: true, Sealed: true, Shares: 5, Threshold: 3, Progress: 0}

		rec := send(t, router, http.MethodGet, "/v1/sys/status", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[statusBody](t, rec)

		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("unseal counts shares and opens at the threshold", func(t *testing.T) {
		router := newRouter(t)
		shares := initialize(t, router)
		steps := []struct {
			progress int
			sealed   bool
		}{
			{1, true},
			{2, true},
			// The buffer empties once the shares are combined.
			{0, false},
		}

		for i, step := range steps {
			got := unseal(t, router, shares[i])

			if got.Progress != step.progress || got.Sealed != step.sealed {
				t.Fatalf("share %d: got progress %d, sealed %t; want %d, %t", i+1, got.Progress, got.Sealed, step.progress, step.sealed)
			}
		}

		if rec := send(t, router, http.MethodGet, "/v1/sys/health", ""); rec.Code != http.StatusNoContent {
			t.Errorf("health: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
	})

	t.Run("seal closes an unsealed instance", func(t *testing.T) {
		router := newRouter(t)
		shares := initialize(t, router)
		for _, share := range shares[:3] {
			unseal(t, router, share)
		}

		rec := send(t, router, http.MethodPost, "/v1/sys/seal", "")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("seal: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if rec := send(t, router, http.MethodGet, "/v1/sys/health", ""); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("health: got %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body)
		}
	})

	t.Run("seal discards a partial unseal", func(t *testing.T) {
		router := newRouter(t)
		shares := initialize(t, router)
		unseal(t, router, shares[0])

		rec := send(t, router, http.MethodPost, "/v1/sys/seal", "")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("seal: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		// Without the discard, the second share after the seal would reach the threshold.
		if got := unseal(t, router, shares[2]); got.Progress != 1 {
			t.Fatalf("share 3: got progress %d, want 1", got.Progress)
		}
		if got := unseal(t, router, shares[3]); got.Progress != 2 || !got.Sealed {
			t.Fatalf("share 4: got %+v, want progress 2, sealed", got)
		}
		if got := unseal(t, router, shares[4]); got.Sealed {
			t.Errorf("share 5: got %+v, want unsealed", got)
		}
	})
}

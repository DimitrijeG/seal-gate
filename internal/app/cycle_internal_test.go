package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

type statusBody struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Shares      int  `json:"shares"`
	Threshold   int  `json:"threshold"`
	Progress    int  `json:"progress"`
}

type secretBody struct {
	Value string `json:"value"`
}

type listBody struct {
	Paths []string `json:"paths"`
}

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

// newRouter wires the real components over a fresh memory backend.
func newRouter(t *testing.T) http.Handler {
	t.Helper()
	return routerOver(t, memory.New())
}

// routerOver wires the real components over backend, with a fresh key holder, so sealed.
func routerOver(t *testing.T, backend storage.Backend) http.Handler {
	t.Helper()
	infra, err := buildInfrastructure(&config.Config{
		Logger: config.LoggerConfig{Level: "error", Format: "text"},
		Crypto: config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
	})
	if err != nil {
		t.Fatalf("buildInfrastructure: %v", err)
	}
	infra.clock = fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	services := buildServices(infra, buildRepositories(backend, infra))
	return buildRouter(services, infra.logger)
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

// unsealAll submits the threshold's worth of shares from initialize.
func unsealAll(t *testing.T, h http.Handler, shares []string) {
	t.Helper()
	for _, share := range shares[:3] {
		unseal(t, h, share)
	}
}

// unsealed returns a router over an initialized, unsealed instance.
func unsealed(t *testing.T) http.Handler {
	t.Helper()
	router := newRouter(t)
	unsealAll(t, router, initialize(t, router))
	return router
}

func putSecret(t *testing.T, h http.Handler, path, value string) {
	t.Helper()
	rec := send(t, h, http.MethodPut, "/v1/secrets/"+path, `{"value":"`+value+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put %s: got %d, want %d: %s", path, rec.Code, http.StatusNoContent, rec.Body)
	}
}

func getSecret(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	rec := send(t, h, http.MethodGet, "/v1/secrets/"+path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get %s: got %d, want %d: %s", path, rec.Code, http.StatusOK, rec.Body)
	}
	return decode[secretBody](t, rec).Value
}

func boltConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{Storage: config.StorageConfig{
		Type: "bolt",
		Path: filepath.Join(t.TempDir(), "seal-gate.db"),
	}}
}

// reopenBolt opens cfg's bolt file and closes it when the test ends.
func reopenBolt(t *testing.T, cfg *config.Config) storage.Backend {
	t.Helper()
	backend, err := buildStorage(t.Context(), cfg)
	if err != nil {
		t.Fatalf("buildStorage: %v", err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return backend
}

// writeOnBolt stores value at db/password on a new instance over cfg's file,
// closes the file, and returns the instance's shares.
func writeOnBolt(t *testing.T, cfg *config.Config, value string) []string {
	t.Helper()
	backend, err := buildStorage(t.Context(), cfg)
	if err != nil {
		t.Fatalf("buildStorage: %v", err)
	}
	router := routerOver(t, backend)
	shares := initialize(t, router)
	unsealAll(t, router, shares)
	putSecret(t, router, "db/password", value)

	// Close releases the file lock; reopening before it would return ErrLocked.
	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return shares
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
		router := unsealed(t)

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

	t.Run("a secret written after unseal reads back", func(t *testing.T) {
		router := unsealed(t)
		want := "c2VjcmV0" // "secret"
		putSecret(t, router, "db/password", want)

		if got := getSecret(t, router, "db/password"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a secret written before a restart reads back after unsealing", func(t *testing.T) {
		cfg := boltConfig(t)
		want := "c2VjcmV0" // "secret"
		shares := writeOnBolt(t, cfg, want)

		router := routerOver(t, reopenBolt(t, cfg))
		unsealAll(t, router, shares)

		if got := getSecret(t, router, "db/password"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("the bolt file holds no form of a stored secret", func(t *testing.T) {
		cfg := boltConfig(t)
		plaintext := "plaintext-canary-4b1d"
		encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
		writeOnBolt(t, cfg, encoded)

		file, err := os.ReadFile(cfg.Storage.Path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}

		// The record is JSON, so an unencrypted value would be stored as base64.
		tests := []struct {
			name string
			form string
		}{
			{"raw", plaintext},
			{"base64", encoded},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if bytes.Contains(file, []byte(tt.form)) {
					t.Errorf("file contains the secret")
				}
			})
		}
	})

	t.Run("writing a secret while sealed is service unavailable", func(t *testing.T) {
		router := newRouter(t)
		initialize(t, router)

		rec := send(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"c2VjcmV0"}`)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body)
		}
	})

	t.Run("secrets list under their prefix", func(t *testing.T) {
		router := unsealed(t)
		want := []string{"db/a", "db/b"}

		for _, path := range []string{"db/a", "db/b", "other"} {
			putSecret(t, router, path, "c2VjcmV0")
		}

		rec := send(t, router, http.MethodGet, "/v1/secrets?prefix=db/", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[listBody](t, rec).Paths

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

package app

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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

type initBody struct {
	Shares    []string `json:"shares"`
	RootToken string   `json:"root_token"`
}

type secretBody struct {
	Value string `json:"value"`
}

type listBody struct {
	Paths []string `json:"paths"`
}

type policyBody struct {
	Rules []ruleBody `json:"rules"`
}

type ruleBody struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

type entityBody struct {
	Policies []string `json:"policies"`
	Groups   []string `json:"groups"`
}

type createEntityBody struct {
	ID string `json:"id"`
}

type tokenBody struct {
	Token string `json:"token"`
}

type groupBody struct {
	Policies []string `json:"policies"`
}

type createGroupBody struct {
	ID string `json:"id"`
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

// The key is part of the stored format, so the test spells it out.
const initializationKey = "sys/initialization"

// unreadableRecord wires a router over a backend holding value at the
// initialization key, bytes no instance would have written.
func unreadableRecord(t *testing.T, value string) (http.Handler, storage.Backend) {
	t.Helper()
	backend := memory.New()
	if err := backend.Put(t.Context(), initializationKey, []byte(value)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return routerOver(t, backend), backend
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

// initialize makes a 3-of-5 instance and returns its shares and root token.
func initialize(t *testing.T, h http.Handler) initBody {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/sys/init", `{"shares":5,"threshold":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("init: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
	}
	return decode[initBody](t, rec)
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
	unsealAll(t, router, initialize(t, router).Shares)
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

// createEntity creates an entity with no policies or groups and returns its ID.
func createEntity(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/entities", `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
	}
	return decode[createEntityBody](t, rec).ID
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
// closes the file, and returns what init returned.
func writeOnBolt(t *testing.T, cfg *config.Config, value string) initBody {
	t.Helper()
	backend, err := buildStorage(t.Context(), cfg)
	if err != nil {
		t.Fatalf("buildStorage: %v", err)
	}
	router := routerOver(t, backend)
	body := initialize(t, router)
	unsealAll(t, router, body.Shares)
	putSecret(t, router, "db/password", value)

	// Close releases the file lock; reopening before it would return ErrLocked.
	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return body
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

	t.Run("init returns a root token", func(t *testing.T) {
		router := newRouter(t)

		token, err := base64.StdEncoding.DecodeString(initialize(t, router).RootToken)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}

		if len(token) != 32 {
			t.Errorf("got %d bytes, want 32", len(token))
		}
	})

	t.Run("status over an unreadable record is a server error", func(t *testing.T) {
		router, _ := unreadableRecord(t, `not json`)

		rec := send(t, router, http.MethodGet, "/v1/sys/status", "")

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body)
		}
	})

	t.Run("init over an unreadable record leaves it in place", func(t *testing.T) {
		stored := `not json`
		router, backend := unreadableRecord(t, stored)

		rec := send(t, router, http.MethodPost, "/v1/sys/init", `{"shares":5,"threshold":3}`)
		if rec.Code == http.StatusOK {
			t.Fatalf("init: got %d, want a refusal", rec.Code)
		}
		got, err := backend.Get(t.Context(), initializationKey)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, []byte(stored)) {
			t.Errorf("got %q, want %q", got, stored)
		}
	})

	t.Run("unseal counts shares and opens at the threshold", func(t *testing.T) {
		router := newRouter(t)
		shares := initialize(t, router).Shares
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
		shares := initialize(t, router).Shares
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
		shares := writeOnBolt(t, cfg, want).Shares

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

	t.Run("the bolt file holds no form of the root token", func(t *testing.T) {
		cfg := boltConfig(t)
		encoded := writeOnBolt(t, cfg, "c2VjcmV0").RootToken
		token, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}

		file, err := os.ReadFile(cfg.Storage.Path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}

		tests := []struct {
			name string
			form []byte
		}{
			{"raw", token},
			{"base64", []byte(encoded)},
			{"hex", []byte(hex.EncodeToString(token))},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if bytes.Contains(file, tt.form) {
					t.Errorf("file contains the root token")
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

	t.Run("a policy written after unseal reads back", func(t *testing.T) {
		router := unsealed(t)
		want := policyBody{Rules: []ruleBody{{Path: "secrets/dev/*", Capabilities: []string{"read", "list"}}}}

		rec := send(t, router, http.MethodPut, "/v1/policies/dev", `{"rules":[{"path":"secrets/dev/*","capabilities":["read","list"]}]}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("put: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		rec = send(t, router, http.MethodGet, "/v1/policies/dev", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("get: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[policyBody](t, rec)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("an entity created after unseal reads back", func(t *testing.T) {
		router := unsealed(t)
		groupID := "fedcba9876543210fedcba9876543210"
		want := entityBody{Policies: []string{"dev"}, Groups: []string{groupID}}

		rec := send(t, router, http.MethodPost, "/v1/entities", `{"policies":["dev"],"groups":["`+groupID+`"]}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		id := decode[createEntityBody](t, rec).ID
		rec = send(t, router, http.MethodGet, "/v1/entities/"+id, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("get: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[entityBody](t, rec)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a token is issued for an entity created after unseal", func(t *testing.T) {
		router := unsealed(t)
		id := createEntity(t, router)

		rec := send(t, router, http.MethodPost, "/v1/entities/"+id+"/tokens", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		token, err := base64.StdEncoding.DecodeString(decode[tokenBody](t, rec).Token)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}

		if len(token) != 32 {
			t.Errorf("got %d bytes, want 32", len(token))
		}
	})

	t.Run("a deleted entity is not issued a token", func(t *testing.T) {
		router := unsealed(t)
		id := createEntity(t, router)
		if rec := send(t, router, http.MethodDelete, "/v1/entities/"+id, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("delete: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		rec := send(t, router, http.MethodPost, "/v1/entities/"+id+"/tokens", "")

		if rec.Code != http.StatusNotFound {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusNotFound, rec.Body)
		}
	})

	t.Run("a group created after unseal reads back", func(t *testing.T) {
		router := unsealed(t)
		want := groupBody{Policies: []string{"dev"}}

		rec := send(t, router, http.MethodPost, "/v1/groups", `{"policies":["dev"]}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		id := decode[createGroupBody](t, rec).ID
		rec = send(t, router, http.MethodGet, "/v1/groups/"+id, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("get: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[groupBody](t, rec)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
}

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
	"github.com/dimitrijegasic/seal-gate/internal/storage/postgres/postgrestest"
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
	Value     string `json:"value"`
	Generated bool   `json:"generated"`
	TTL       int64  `json:"ttl"`
	ExpiresAt string `json:"expires_at"`
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

type entitySummaryBody struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
}

type groupSummaryBody struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
}

type userSummaryBody struct {
	Name     string `json:"name"`
	EntityID string `json:"entity_id"`
}

type tokenBody struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type tokenSelfBody struct {
	Root      bool   `json:"root"`
	EntityID  string `json:"entity_id"`
	ExpiresAt string `json:"expires_at"`
}

type groupBody struct {
	Policies []string `json:"policies"`
}

type createGroupBody struct {
	ID string `json:"id"`
}

// fakeClock reads as now; tests move it with advance. Locked, as the worker's ticker reads it from its own goroutine.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
}

// newRouter wires the real components over a fresh memory backend.
func newRouter(t *testing.T) http.Handler {
	t.Helper()
	return routerOver(t, memory.New())
}

// auditedRouter is newRouter that also returns the path of the file it audits to.
func auditedRouter(t *testing.T) (http.Handler, string) {
	t.Helper()
	return auditedRouterOver(t, memory.New())
}

// routerOver wires the real components over backend, with a fresh key holder, so sealed.
func routerOver(t *testing.T, backend storage.Backend) http.Handler {
	t.Helper()
	router, _ := auditedRouterOver(t, backend)
	return router
}

// auditedRouterOver is routerOver that also returns the path of the file it audits to.
func auditedRouterOver(t *testing.T, backend storage.Backend) (http.Handler, string) {
	t.Helper()
	return clockedRouterOver(t, backend, newFakeClock())
}

// clockedRouterOver is auditedRouterOver on a clock the caller holds.
func clockedRouterOver(t *testing.T, backend storage.Backend, clock *fakeClock) (http.Handler, string) {
	t.Helper()
	i := newInstance(t, backend, clock, time.Hour)
	return i.router, i.auditPath
}

// instance is one wired service: its router, the file it audits to, its services, and what it logged.
type instance struct {
	router    http.Handler
	auditPath string
	services  *services
	backend   storage.Backend
	log       *bytes.Buffer
}

// newInstance wires the real components over backend and clock, sweeping every interval while unsealed.
// The cycle tests that drive Tick pass an hour, so the ticker never runs beside them.
func newInstance(t testing.TB, backend storage.Backend, clock *fakeClock, interval time.Duration) instance {
	t.Helper()
	infra, err := buildInfrastructure(&config.Config{
		Logger: config.LoggerConfig{Level: "error", Format: "text"},
		Crypto: config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
	})
	if err != nil {
		t.Fatalf("buildInfrastructure: %v", err)
	}
	log := &bytes.Buffer{}
	infra.logger = slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelError}))
	infra.clock = clock

	auditor, path := fileAuditor(t, infra.logger)
	services, err := buildServices(infra, buildRepositories(backend, infra), auditor, interval, config.TokenConfig{DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("buildServices: %v", err)
	}
	// Registered after the sink's, so it runs first: the worker stops before its audit file closes.
	t.Cleanup(func() {
		if err := services.system.Seal(context.Background(), authorization.NewRootPrincipal()); err != nil {
			t.Errorf("Seal: %v", err)
		}
	})
	return instance{router: buildRouter(services, infra, auditor), auditPath: path, services: services, backend: backend, log: log}
}

// unsealedInstance is newInstance over a fresh memory backend, initialized and unsealed, with a router sending
// its root token.
func unsealedInstance(t *testing.T, interval time.Duration) (instance, http.Handler, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	i := newInstance(t, memory.New(), clock, interval)
	body := initialize(t, i.router)
	unsealAll(t, i.router, body.Shares)
	return i, withToken(i.router, body.RootToken), clock
}

// fileAuditor records to a real file sink, so every cycle test is audited as production is, and returns its path.
func fileAuditor(t testing.TB, logger *slog.Logger) (*audit.FanOut, string) {
	t.Helper()
	a, dir := newAuditApplication(t)
	path := filepath.Join(dir, "audit.log")
	destinations, err := a.auditDestinations(auditConfig(config.AuditSinkConfig{
		Type: "file", Path: path, Required: true, Timeout: time.Second,
	}))
	if err != nil {
		t.Fatalf("auditDestinations: %v", err)
	}
	auditor, err := audit.New(logger, destinations...)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	return auditor, path
}

// auditLine is one line of the audit file, as an operator reads it.
type auditLine struct {
	RequestID string `json:"request_id"`
	Kind      string `json:"kind"`
	Principal string `json:"principal"`
	Route     string `json:"route"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
}

// auditedSecret is the secret value the audited actions write, raw.
const auditedSecret = "hunter2-database-password"

// auditActions initializes, unseals, writes a secret as root and reads it without a token,
// then returns what init handed out and the audit file's bytes.
func auditActions(t *testing.T) (initBody, []byte) {
	t.Helper()
	router, path := auditedRouter(t)
	body := initialize(t, router)
	unsealAll(t, router, body.Shares)
	putSecret(t, withToken(router, body.RootToken), "db/password", base64.StdEncoding.EncodeToString([]byte(auditedSecret)))
	if rec := send(t, router, http.MethodGet, "/v1/secrets/db/password", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("get: got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return body, written
}

// auditLines decodes every line of an audit file.
func auditLines(t *testing.T, written []byte) []auditLine {
	t.Helper()
	var lines []auditLine
	for raw := range bytes.Lines(written) {
		var line auditLine
		if err := json.Unmarshal(raw, &line); err != nil {
			t.Fatalf("Unmarshal %q: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
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

func send(t testing.TB, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t testing.TB, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return v
}

// initialize makes a 3-of-5 instance and returns its shares and root token.
func initialize(t testing.TB, h http.Handler) initBody {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/sys/init", `{"shares":5,"threshold":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("init: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
	}
	return decode[initBody](t, rec)
}

func unseal(t testing.TB, h http.Handler, share string) statusBody {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/sys/unseal", fmt.Sprintf(`{"share":%q}`, share))
	if rec.Code != http.StatusOK {
		t.Fatalf("unseal: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
	}
	return decode[statusBody](t, rec)
}

// unsealAll submits the threshold's worth of shares from initialize.
func unsealAll(t testing.TB, h http.Handler, shares []string) {
	t.Helper()
	for _, share := range shares[:3] {
		unseal(t, h, share)
	}
}

// withToken sends token as a bearer token on every request that does not carry one.
func withToken(h http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		h.ServeHTTP(w, r)
	})
}

// unsealed returns a router over an initialized, unsealed instance, sending its root token.
func unsealed(t *testing.T) http.Handler {
	t.Helper()
	router, _ := clockedUnsealed(t)
	return router
}

// clockedUnsealed is unsealed that also returns the clock the instance reads, for the test to move.
func clockedUnsealed(t *testing.T) (http.Handler, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	router, _ := clockedRouterOver(t, memory.New(), clock)
	body := initialize(t, router)
	unsealAll(t, router, body.Shares)
	return withToken(router, body.RootToken), clock
}

func putSecret(t testing.TB, h http.Handler, path, value string) {
	t.Helper()
	rec := send(t, h, http.MethodPut, "/v1/secrets/"+path, `{"value":"`+value+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put %s: got %d, want %d: %s", path, rec.Code, http.StatusNoContent, rec.Body)
	}
}

func getSecret(t testing.TB, h http.Handler, path string) string {
	t.Helper()
	rec := send(t, h, http.MethodGet, "/v1/secrets/"+path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get %s: got %d, want %d: %s", path, rec.Code, http.StatusOK, rec.Body)
	}
	return decode[secretBody](t, rec).Value
}

func generateSecret(t *testing.T, h http.Handler, path string, length int) string {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/secrets/generate/"+path, fmt.Sprintf(`{"length":%d}`, length))
	if rec.Code != http.StatusCreated {
		t.Fatalf("generate %s: got %d, want %d: %s", path, rec.Code, http.StatusCreated, rec.Body)
	}
	return decode[secretBody](t, rec).Value
}

func rotateSecret(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/secrets/rotate/"+path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate %s: got %d, want %d: %s", path, rec.Code, http.StatusOK, rec.Body)
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

// entityToken has root write policy dev with rules, a group holding it, an entity in the group,
// and returns a token for that entity.
func entityToken(t testing.TB, h http.Handler, rules string) string {
	t.Helper()
	return entityTokenWith(t, h, rules, "")
}

// entityTokenWith is entityToken that sends body with the token request.
func entityTokenWith(t testing.TB, h http.Handler, rules, body string) string {
	t.Helper()
	if rec := send(t, h, http.MethodPut, "/v1/policies/dev", `{"rules":`+rules+`}`); rec.Code != http.StatusNoContent {
		t.Fatalf("put policy: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
	}

	rec := send(t, h, http.MethodPost, "/v1/groups", `{"policies":["dev"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
	}
	groupID := decode[createGroupBody](t, rec).ID

	rec = send(t, h, http.MethodPost, "/v1/entities", `{"groups":["`+groupID+`"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create entity: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
	}
	entityID := decode[createEntityBody](t, rec).ID

	rec = send(t, h, http.MethodPost, "/v1/entities/"+entityID+"/tokens", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue token: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
	}
	return decode[tokenBody](t, rec).Token
}

// setUser has root write policy dev with rules, an entity holding it, and user name with password for that entity.
func setUser(t testing.TB, h http.Handler, name, password, rules string) {
	t.Helper()
	if rec := send(t, h, http.MethodPut, "/v1/policies/dev", `{"rules":`+rules+`}`); rec.Code != http.StatusNoContent {
		t.Fatalf("put policy: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
	}

	rec := send(t, h, http.MethodPost, "/v1/entities", `{"policies":["dev"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create entity: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
	}
	entityID := decode[createEntityBody](t, rec).ID

	rec = send(t, h, http.MethodPut, "/v1/auth/users/"+name, `{"entity_id":"`+entityID+`","password":"`+password+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set user: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
	}
}

// rotateToken rotates the token h sends and returns the new one.
func rotateToken(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := send(t, h, http.MethodPost, "/v1/auth/token/rotate", "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotate: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
	}
	return decode[tokenBody](t, rec).Token
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
	putSecret(t, withToken(router, body.RootToken), "db/password", value)

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

	t.Run("reset discards a partial unseal", func(t *testing.T) {
		router := newRouter(t)
		shares := initialize(t, router).Shares
		unseal(t, router, shares[0])

		rec := send(t, router, http.MethodPost, "/v1/sys/unseal", `{"reset":true}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("reset: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		if got := decode[statusBody](t, rec); got.Progress != 0 {
			t.Fatalf("reset: got progress %d, want 0", got.Progress)
		}

		// Without the discard, the second share after the reset would reach the threshold.
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

	t.Run("a request without a token is unauthorized", func(t *testing.T) {
		router := newRouter(t)
		unsealAll(t, router, initialize(t, router).Shares)

		rec := send(t, router, http.MethodGet, "/v1/secrets?prefix=", "")

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
		}
	})

	t.Run("a token never issued is unauthorized", func(t *testing.T) {
		router := newRouter(t)
		unsealAll(t, router, initialize(t, router).Shares)
		token := base64.StdEncoding.EncodeToString(make([]byte, 32))

		rec := send(t, withToken(router, token), http.MethodGet, "/v1/secrets?prefix=", "")

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
		}
	})

	t.Run("a token reads a secret its group's policy grants", func(t *testing.T) {
		router := unsealed(t)
		want := "c2VjcmV0" // "secret"
		putSecret(t, router, "dev/a", want)
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)

		if got := getSecret(t, withToken(router, token), "dev/a"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a user logs in and its token reads a secret its policy grants", func(t *testing.T) {
		router := unsealed(t)
		want := "c2VjcmV0" // "secret"
		putSecret(t, router, "dev/a", want)
		setUser(t, router, "alice", "correct horse", `[{"path":"secrets/dev/*","capabilities":["read"]}]`)

		rec := send(t, router, http.MethodPost, "/v1/auth/login", `{"username":"alice","password":"correct horse"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("login: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		token := decode[tokenBody](t, rec).Token

		if got := getSecret(t, withToken(router, token), "dev/a"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a login with a wrong password is unauthorized", func(t *testing.T) {
		router := unsealed(t)
		setUser(t, router, "alice", "correct horse", `[]`)

		rec := send(t, router, http.MethodPost, "/v1/auth/login", `{"username":"alice","password":"wrong horse"}`)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
		}
	})

	t.Run("a token issued with a ttl stops working after it", func(t *testing.T) {
		router, clock := clockedUnsealed(t)
		putSecret(t, router, "dev/a", "c2VjcmV0")
		// A minute, so a token given the hour-long default would still work.
		token := entityTokenWith(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`, `{"ttl":60}`)
		clock.advance(time.Minute)

		rec := send(t, withToken(router, token), http.MethodGet, "/v1/secrets/dev/a", "")

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
		}
	})

	t.Run("a token is refused once the clock passes its expiry", func(t *testing.T) {
		router, clock := clockedUnsealed(t)
		putSecret(t, router, "dev/a", "c2VjcmV0")
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)
		if rec := send(t, withToken(router, token), http.MethodGet, "/v1/secrets/dev/a", ""); rec.Code != http.StatusOK {
			t.Fatalf("read before expiry: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		clock.advance(time.Hour)

		rec := send(t, withToken(router, token), http.MethodGet, "/v1/secrets/dev/a", "")

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
		}
	})

	t.Run("a revoked token gets 401 at once", func(t *testing.T) {
		router := unsealed(t)
		putSecret(t, router, "dev/a", "c2VjcmV0")
		token := withToken(router, entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`))
		getSecret(t, token, "dev/a")
		if rec := send(t, token, http.MethodPost, "/v1/auth/token/revoke", ""); rec.Code != http.StatusNoContent {
			t.Fatalf("revoke: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		rec := send(t, token, http.MethodGet, "/v1/secrets/dev/a", "")

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
		}
	})

	t.Run("a rotated token's old value gets 401", func(t *testing.T) {
		router := unsealed(t)
		putSecret(t, router, "dev/a", "c2VjcmV0")
		old := withToken(router, entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`))
		rotateToken(t, old)

		rec := send(t, old, http.MethodGet, "/v1/secrets/dev/a", "")

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body)
		}
	})

	t.Run("a rotated token's new value works", func(t *testing.T) {
		router := unsealed(t)
		want := "c2VjcmV0" // "secret"
		putSecret(t, router, "dev/a", want)
		old := withToken(router, entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`))

		token := rotateToken(t, old)

		if got := getSecret(t, withToken(router, token), "dev/a"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a token is forbidden a secret no policy grants", func(t *testing.T) {
		router := unsealed(t)
		putSecret(t, router, "prod/a", "c2VjcmV0")
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)

		rec := send(t, withToken(router, token), http.MethodGet, "/v1/secrets/prod/a", "")

		if rec.Code != http.StatusForbidden {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body)
		}
	})

	t.Run("a token is forbidden a policy no rule grants", func(t *testing.T) {
		router := unsealed(t)
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)

		rec := send(t, withToken(router, token), http.MethodGet, "/v1/policies/dev", "")

		if rec.Code != http.StatusForbidden {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body)
		}
	})

	t.Run("a token is forbidden an entity no rule grants", func(t *testing.T) {
		router := unsealed(t)
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)

		rec := send(t, withToken(router, token), http.MethodPost, "/v1/entities", `{}`)

		if rec.Code != http.StatusForbidden {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body)
		}
	})

	t.Run("a token issues tokens where its policy grants create", func(t *testing.T) {
		router := unsealed(t)
		entityID := createEntity(t, router)
		token := entityToken(t, router, `[{"path":"system/entities/*","capabilities":["create"]}]`)

		rec := send(t, withToken(router, token), http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")

		if rec.Code != http.StatusCreated {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
	})

	t.Run("a token lists entities with their aliases where its policy grants list on the collection", func(t *testing.T) {
		router := unsealed(t)
		rec := send(t, router, http.MethodPost, "/v1/entities", `{"alias":"ci"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create entity: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		want := entitySummaryBody{ID: decode[createEntityBody](t, rec).ID, Alias: "ci"}
		token := entityToken(t, router, `[{"path":"system/entities","capabilities":["list"]}]`)

		rec = send(t, withToken(router, token), http.MethodGet, "/v1/entities", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[struct {
			Entities []entitySummaryBody `json:"entities"`
		}](t, rec).Entities

		if !slices.Contains(got, want) {
			t.Errorf("got %+v, want it to hold %+v", got, want)
		}
	})

	t.Run("groups are listed with their aliases", func(t *testing.T) {
		router := unsealed(t)
		rec := send(t, router, http.MethodPost, "/v1/groups", `{"alias":"ops"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create group: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		want := groupSummaryBody{ID: decode[createGroupBody](t, rec).ID, Alias: "ops"}

		rec = send(t, router, http.MethodGet, "/v1/groups", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[struct {
			Groups []groupSummaryBody `json:"groups"`
		}](t, rec).Groups

		if !slices.Contains(got, want) {
			t.Errorf("got %+v, want it to hold %+v", got, want)
		}
	})

	t.Run("users are listed with the entity each logs in as", func(t *testing.T) {
		router := unsealed(t)
		entityID := createEntity(t, router)
		rec := send(t, router, http.MethodPut, "/v1/auth/users/alice", `{"entity_id":"`+entityID+`","password":"correct horse"}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("set user: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		want := []userSummaryBody{{Name: "alice", EntityID: entityID}}

		rec = send(t, router, http.MethodGet, "/v1/auth/users", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[struct {
			Users []userSummaryBody `json:"users"`
		}](t, rec).Users

		if !slices.Equal(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a user set after unseal reads back with its entity", func(t *testing.T) {
		router := unsealed(t)
		entityID := createEntity(t, router)
		rec := send(t, router, http.MethodPut, "/v1/auth/users/alice", `{"entity_id":"`+entityID+`","password":"correct horse"}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("set user: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		rec = send(t, router, http.MethodGet, "/v1/auth/users/alice", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[struct {
			EntityID string `json:"entity_id"`
		}](t, rec).EntityID

		if got != entityID {
			t.Errorf("got %q, want %q", got, entityID)
		}
	})

	t.Run("an issued token looks itself up as its entity and expiry", func(t *testing.T) {
		router := unsealed(t)
		entityID := createEntity(t, router)
		rec := send(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue token: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		issued := decode[tokenBody](t, rec)
		want := tokenSelfBody{EntityID: entityID, ExpiresAt: issued.ExpiresAt}

		rec = send(t, withToken(router, issued.Token), http.MethodGet, "/v1/auth/token/self", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if got := decode[tokenSelfBody](t, rec); got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the root token looks itself up as root", func(t *testing.T) {
		router := unsealed(t)
		want := tokenSelfBody{Root: true}

		rec := send(t, router, http.MethodGet, "/v1/auth/token/self", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if got := decode[tokenSelfBody](t, rec); got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a token's rules include its group's policies", func(t *testing.T) {
		router := unsealed(t)
		policies := map[string]string{
			"own": `{"rules":[{"path":"secrets/own/*","capabilities":["read"]}]}`,
			"dev": `{"rules":[{"path":"secrets/dev/*","capabilities":["list"]}]}`,
		}
		for name, body := range policies {
			if rec := send(t, router, http.MethodPut, "/v1/policies/"+name, body); rec.Code != http.StatusNoContent {
				t.Fatalf("put policy: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
			}
		}
		rec := send(t, router, http.MethodPost, "/v1/groups", `{"policies":["dev"]}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create group: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		groupID := decode[createGroupBody](t, rec).ID
		rec = send(t, router, http.MethodPost, "/v1/entities", `{"policies":["own"],"groups":["`+groupID+`"]}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create entity: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		entityID := decode[createEntityBody](t, rec).ID
		rec = send(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue token: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		token := decode[tokenBody](t, rec).Token
		// The entity's own policies come before its groups'.
		want := policyBody{Rules: []ruleBody{
			{Path: "secrets/own/*", Capabilities: []string{"read"}},
			{Path: "secrets/dev/*", Capabilities: []string{"list"}},
		}}

		rec = send(t, withToken(router, token), http.MethodGet, "/v1/auth/token/self/rules", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if got := decode[policyBody](t, rec); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the root token's rules report it as root", func(t *testing.T) {
		router := unsealed(t)
		want := `{"root":true}`

		rec := send(t, router, http.MethodGet, "/v1/auth/token/self/rules", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if got := strings.TrimSpace(rec.Body.String()); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a token is forbidden a listing granted only beneath the collection", func(t *testing.T) {
		router := unsealed(t)
		token := entityToken(t, router, `[{"path":"system/policies/*","capabilities":["list"]}]`)

		rec := send(t, withToken(router, token), http.MethodGet, "/v1/policies", "")

		if rec.Code != http.StatusForbidden {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body)
		}
	})

	t.Run("creating an entity with a taken alias is a conflict", func(t *testing.T) {
		router := unsealed(t)
		rec := send(t, router, http.MethodPost, "/v1/entities", `{"alias":"ci"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("first create: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		rec = send(t, router, http.MethodPost, "/v1/entities", `{"alias":"ci"}`)

		if rec.Code != http.StatusConflict {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body)
		}
	})

	t.Run("creating a group with a taken alias is a conflict", func(t *testing.T) {
		router := unsealed(t)
		rec := send(t, router, http.MethodPost, "/v1/groups", `{"alias":"ops"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("first create: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		rec = send(t, router, http.MethodPost, "/v1/groups", `{"alias":"ops"}`)

		if rec.Code != http.StatusConflict {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body)
		}
	})

	t.Run("a token is forbidden a group no rule grants", func(t *testing.T) {
		router := unsealed(t)
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)

		rec := send(t, withToken(router, token), http.MethodPost, "/v1/groups", `{}`)

		if rec.Code != http.StatusForbidden {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body)
		}
	})

	t.Run("a token reads a group its policy grants", func(t *testing.T) {
		router := unsealed(t)
		rec := send(t, router, http.MethodPost, "/v1/groups", `{}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create group: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		groupID := decode[createGroupBody](t, rec).ID
		token := entityToken(t, router, `[{"path":"system/groups/*","capabilities":["read"]}]`)

		rec = send(t, withToken(router, token), http.MethodGet, "/v1/groups/"+groupID, "")

		if rec.Code != http.StatusOK {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
	})

	t.Run("a token is forbidden the seal no rule grants", func(t *testing.T) {
		router := unsealed(t)
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)

		rec := send(t, withToken(router, token), http.MethodPost, "/v1/sys/seal", "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("seal: got %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body)
		}

		if rec := send(t, router, http.MethodGet, "/v1/sys/health", ""); rec.Code != http.StatusNoContent {
			t.Errorf("health: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
	})

	t.Run("a token seals where its policy grants update", func(t *testing.T) {
		router := unsealed(t)
		token := entityToken(t, router, `[{"path":"system/seal","capabilities":["update"]}]`)

		rec := send(t, withToken(router, token), http.MethodPost, "/v1/sys/seal", "")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("seal: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if rec := send(t, router, http.MethodGet, "/v1/sys/health", ""); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("health: got %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body)
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
		body := writeOnBolt(t, cfg, want)

		router := routerOver(t, reopenBolt(t, cfg))
		unsealAll(t, router, body.Shares)

		if got := getSecret(t, withToken(router, body.RootToken), "db/password"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("the lifecycle runs over postgres", func(t *testing.T) {
		backend, err := buildStorage(t.Context(), &config.Config{Storage: config.StorageConfig{
			Type: "postgres",
			URL:  postgrestest.SchemaURL(t),
		}})
		if err != nil {
			t.Fatalf("buildStorage: %v", err)
		}
		t.Cleanup(func() {
			if err := backend.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
		router := routerOver(t, backend)
		body := initialize(t, router)
		unsealAll(t, router, body.Shares)
		root := withToken(router, body.RootToken)
		want := "c2VjcmV0" // "secret"
		putSecret(t, root, "db/password", want)

		if got := getSecret(t, root, "db/password"); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
		if rec := send(t, root, http.MethodPost, "/v1/sys/seal", ""); rec.Code != http.StatusNoContent {
			t.Errorf("seal: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
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
		token := initialize(t, router).RootToken

		rec := send(t, withToken(router, token), http.MethodPut, "/v1/secrets/db/password", `{"value":"c2VjcmV0"}`)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body)
		}
	})

	t.Run("a generated secret rotates to a new value of the same length", func(t *testing.T) {
		router := unsealed(t)
		generated := generateSecret(t, router, "db/password", 32)

		rotated := rotateSecret(t, router, "db/password")

		if rotated == generated {
			t.Errorf("value: got %q, want a value other than %q", rotated, generated)
		}
		if len(rotated) != len(generated) {
			t.Errorf("length: got %d base64 bytes, want %d", len(rotated), len(generated))
		}
	})

	t.Run("a rotated secret reads back as its new value", func(t *testing.T) {
		router := unsealed(t)
		generateSecret(t, router, "db/password", 32)
		want := rotateSecret(t, router, "db/password")

		if got := getSecret(t, router, "db/password"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a generated secret reads back as generated", func(t *testing.T) {
		router := unsealed(t)
		generateSecret(t, router, "db/password", 32)

		rec := send(t, router, http.MethodGet, "/v1/secrets/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("get: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if got := decode[secretBody](t, rec).Generated; !got {
			t.Errorf("got %v, want true", got)
		}
	})

	t.Run("a secret's TTL reads back in seconds", func(t *testing.T) {
		router := unsealed(t)
		rec := send(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32,"ttl":3600}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("generate: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		rec = send(t, router, http.MethodGet, "/v1/secrets/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("get: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if got := decode[secretBody](t, rec).TTL; got != 3600 {
			t.Errorf("got %d, want 3600", got)
		}
	})

	t.Run("rotating a stored secret is a conflict", func(t *testing.T) {
		router := unsealed(t)
		putSecret(t, router, "db/password", "c2VjcmV0")

		rec := send(t, router, http.MethodPost, "/v1/secrets/rotate/db/password", "")

		if rec.Code != http.StatusConflict {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body)
		}
	})

	t.Run("a secret written with a TTL is not found after its expiry", func(t *testing.T) {
		router, clock := clockedUnsealed(t)
		rec := send(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"c2VjcmV0","ttl":3600}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("put: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		getSecret(t, router, "db/password")
		clock.advance(time.Hour)

		rec = send(t, router, http.MethodGet, "/v1/secrets/db/password", "")

		if rec.Code != http.StatusNotFound {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusNotFound, rec.Body)
		}
	})

	t.Run("a rotated secret's expiry moves forward", func(t *testing.T) {
		router, clock := clockedUnsealed(t)
		rec := send(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32,"ttl":3600}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("generate: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		clock.advance(90 * time.Minute)
		want := clock.Now().Add(time.Hour).Format(time.RFC3339)
		rotateSecret(t, router, "db/password")

		rec = send(t, router, http.MethodGet, "/v1/secrets/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("get: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if got := decode[secretBody](t, rec).ExpiresAt; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("after a tick past its expiry, a generated secret reads a new value", func(t *testing.T) {
		i, router, clock := unsealedInstance(t, time.Hour)
		rec := send(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32,"ttl":3600}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("generate: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		generated := decode[secretBody](t, rec).Value
		clock.advance(time.Hour)

		i.services.worker.Tick(t.Context())

		if got := getSecret(t, router, "db/password"); got == generated {
			t.Errorf("got %q, want a value other than %q", got, generated)
		}
	})

	t.Run("after a tick past its expiry, a stored secret is gone from storage", func(t *testing.T) {
		i, router, clock := unsealedInstance(t, time.Hour)
		rec := send(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"c2VjcmV0","ttl":3600}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("put: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		clock.advance(time.Hour)

		i.services.worker.Tick(t.Context())

		// The API already reads an expired secret as not found; only storage shows the sweep deleted it.
		if _, err := i.backend.Get(t.Context(), "secrets/db/password"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("after a tick past its expiry, a token is gone from storage", func(t *testing.T) {
		i, router, clock := unsealedInstance(t, time.Hour)
		token := entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)
		raw, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}
		hash := sha256.Sum256(raw)
		clock.advance(time.Hour)

		i.services.worker.Tick(t.Context())

		// The API already refuses an expired token; only storage shows the purge deleted it.
		if _, err := i.backend.Get(t.Context(), "tokens/"+hex.EncodeToString(hash[:])); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("a tick's actions are in the audit file", func(t *testing.T) {
		i, router, clock := unsealedInstance(t, time.Hour)
		rec := send(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32,"ttl":3600}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("generate: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		rec = send(t, router, http.MethodPut, "/v1/secrets/db/user", `{"value":"c2VjcmV0","ttl":3600}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("put: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		clock.advance(time.Hour)
		want := map[string]string{"secrets/db/password": "rotate secret", "secrets/db/user": "expire secret"}

		i.services.worker.Tick(t.Context())

		written, err := os.ReadFile(i.auditPath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		got := make(map[string]string)
		for _, line := range auditLines(t, written) {
			if line.Kind == "lifecycle" {
				got[line.Path] = line.Route
			}
		}
		if !maps.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a tick's token purge is in the audit file without the token", func(t *testing.T) {
		i, router, clock := unsealedInstance(t, time.Hour)
		entityToken(t, router, `[{"path":"secrets/dev/*","capabilities":["read"]}]`)
		clock.advance(time.Hour)
		want := map[string]string{"": "expire token"}

		i.services.worker.Tick(t.Context())

		written, err := os.ReadFile(i.auditPath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		got := make(map[string]string)
		for _, line := range auditLines(t, written) {
			if line.Kind == "lifecycle" {
				got[line.Path] = line.Route
			}
		}
		if !maps.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the worker ticks on its own while unsealed", func(t *testing.T) {
		i, router, clock := unsealedInstance(t, time.Millisecond)
		rec := send(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"c2VjcmV0","ttl":3600}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("put: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		clock.advance(time.Hour)

		deadline := time.Now().Add(time.Second)
		for {
			_, err := i.backend.Get(t.Context(), "secrets/db/password")
			if errors.Is(err, storage.ErrNotFound) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("got %v after a second, want %v", err, storage.ErrNotFound)
			}
			time.Sleep(time.Millisecond)
		}
	})

	t.Run("after seal, no tick runs", func(t *testing.T) {
		i, router, _ := unsealedInstance(t, time.Millisecond)
		if rec := send(t, router, http.MethodPost, "/v1/sys/seal", ""); rec.Code != http.StatusNoContent {
			t.Fatalf("seal: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		// A tick while sealed fails its jobs on the missing key, and logs it.
		time.Sleep(20 * time.Millisecond)

		if got := i.log.String(); strings.Contains(got, "lifecycle job failed") {
			t.Errorf("got %q, want no job after seal", got)
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

	t.Run("a listing leaves out a denied subtree", func(t *testing.T) {
		router := unsealed(t)
		want := []string{"dev/x"}

		for _, path := range []string{"dev/x", "hr/x"} {
			putSecret(t, router, path, "c2VjcmV0")
		}
		token := entityToken(t, router, `[{"path":"secrets/*","capabilities":["list"]},{"path":"secrets/hr/*","capabilities":["deny"]}]`)

		rec := send(t, withToken(router, token), http.MethodGet, "/v1/secrets?prefix=", "")
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

	t.Run("init, unseal, a secret write and a refused read are in the audit file", func(t *testing.T) {
		type action struct {
			route  string
			status int
		}
		want := map[action]int{
			{"POST /v1/sys/init", http.StatusOK}:                   1,
			{"POST /v1/sys/unseal", http.StatusOK}:                 3,
			{"PUT /v1/secrets/{path...}", http.StatusNoContent}:    1,
			{"GET /v1/secrets/{path...}", http.StatusUnauthorized}: 1,
		}

		_, written := auditActions(t)

		// A request line and its response line share an ID; the response holds the status.
		requests := make(map[string]auditLine)
		got := make(map[action]int)
		for _, line := range auditLines(t, written) {
			switch line.Kind {
			case "request":
				requests[line.RequestID] = line
			case "response":
				if request, ok := requests[line.RequestID]; ok {
					got[action{request.Route, line.Status}]++
				}
			}
		}
		if !maps.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the audit file holds no secret", func(t *testing.T) {
		body, written := auditActions(t)
		// An empty file holds no secret either; that would prove nothing.
		if len(written) == 0 {
			t.Fatalf("got an empty audit file, want the actions' lines")
		}
		secrets := map[string]string{"secret value": auditedSecret, "root token": body.RootToken}
		for i, share := range body.Shares {
			secrets[fmt.Sprintf("share %d", i)] = share
		}

		for name, encoded := range secrets {
			// Each is checked as sent and as its raw bytes, whichever form it was handed out in.
			forms := [][]byte{[]byte(encoded)}
			if raw, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				forms = append(forms, raw)
			} else {
				forms = append(forms, []byte(base64.StdEncoding.EncodeToString([]byte(encoded))))
			}
			for _, form := range forms {
				if bytes.Contains(written, form) {
					t.Errorf("got the %s in the audit file, want none", name)
				}
			}
		}
	})

	t.Run("a secret write is recorded as root", func(t *testing.T) {
		_, written := auditActions(t)

		var got []string
		for _, line := range auditLines(t, written) {
			if line.Kind == "request" && line.Route == "PUT /v1/secrets/{path...}" {
				got = append(got, line.Principal)
			}
		}

		if want := []string{"root"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

// BenchmarkSecretRead reads a 1 KiB secret through the real router, auth and file audit, over memory.
func BenchmarkSecretRead(b *testing.B) {
	i := newInstance(b, memory.New(), newFakeClock(), time.Hour)
	body := initialize(b, i.router)
	unsealAll(b, i.router, body.Shares)
	root := withToken(i.router, body.RootToken)
	want := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 1024))
	putSecret(b, root, "bench/a", want)
	// Root skips policy evaluation; the entity's token pays for it.
	readers := []struct {
		name   string
		router http.Handler
	}{
		{"root", root},
		{"entity", withToken(i.router, entityToken(b, root, `[{"path":"secrets/bench/*","capabilities":["read"]}]`))},
	}

	for _, reader := range readers {
		b.Run(reader.name, func(b *testing.B) {
			b.ReportAllocs()
			if got := getSecret(b, reader.router, "bench/a"); got != want {
				b.Fatalf("got %q, want %q", got, want)
			}

			for b.Loop() {
				if rec := send(b, reader.router, http.MethodGet, "/v1/secrets/bench/a", ""); rec.Code != http.StatusOK {
					b.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
				}
			}
		})
	}
}

// BenchmarkUnseal times the threshold of unseal requests; the seal before each is untimed setup.
func BenchmarkUnseal(b *testing.B) {
	i := newInstance(b, memory.New(), newFakeClock(), time.Hour)
	body := initialize(b, i.router)
	// Unsealed first: a sealed instance cannot check the root token, so the first seal would be refused.
	unsealAll(b, i.router, body.Shares)
	root := withToken(i.router, body.RootToken)
	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		if rec := send(b, root, http.MethodPost, "/v1/sys/seal", ""); rec.Code != http.StatusNoContent {
			b.Fatalf("seal: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		b.StartTimer()

		var got statusBody
		for _, share := range body.Shares[:3] {
			got = unseal(b, i.router, share)
		}
		if got.Sealed {
			b.Fatalf("got %+v, want unsealed", got)
		}
	}
}

// BenchmarkLogin times a login through the real router; an unknown user verifies against the dummy hash, so it should
// cost what a wrong password does.
func BenchmarkLogin(b *testing.B) {
	i := newInstance(b, memory.New(), newFakeClock(), time.Hour)
	body := initialize(b, i.router)
	unsealAll(b, i.router, body.Shares)
	setUser(b, withToken(i.router, body.RootToken), "alice", "correct horse", `[]`)
	logins := []struct {
		name   string
		body   string
		status int
	}{
		{"known user", `{"username":"alice","password":"correct horse"}`, http.StatusCreated},
		{"unknown user", `{"username":"bob","password":"correct horse"}`, http.StatusUnauthorized},
		{"wrong password", `{"username":"alice","password":"wrong horse"}`, http.StatusUnauthorized},
	}

	for _, login := range logins {
		b.Run(login.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				if rec := send(b, i.router, http.MethodPost, "/v1/auth/login", login.body); rec.Code != login.status {
					b.Fatalf("got %d, want %d: %s", rec.Code, login.status, rec.Body)
				}
			}
		})
	}
}

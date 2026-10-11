package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/dimitrijegasic/seal-gate/internal/secret"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

// SystemService is the seal lifecycle as the handlers use it.
type SystemService interface {
	Init(ctx context.Context, cfg system.SealConfiguration) (system.InitResult, error)
	Unseal(ctx context.Context, share []byte) (system.Status, error)
	Seal(ctx context.Context)
	Status(ctx context.Context) (system.Status, error)
}

// SecretService is secret storage as the handlers use it.
type SecretService interface {
	Put(ctx context.Context, path string, value []byte) error
	Get(ctx context.Context, path string) ([]byte, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// Handlers holds what the HTTP handlers call.
type Handlers struct {
	System SystemService
	Secret SecretService
	Logger *slog.Logger
}

func NewRouter(h *Handlers) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/sys/init", h.handleInit)
	mux.HandleFunc("POST /v1/sys/unseal", h.handleUnseal)
	mux.HandleFunc("POST /v1/sys/seal", h.handleSeal)
	mux.HandleFunc("GET /v1/sys/status", h.handleStatus)
	mux.HandleFunc("GET /v1/sys/health", h.handleHealth)

	mux.HandleFunc("GET /v1/secrets", h.handleListSecrets)
	mux.HandleFunc("PUT /v1/secrets/{path...}", h.handlePutSecret)
	mux.HandleFunc("GET /v1/secrets/{path...}", h.handleGetSecret)
	mux.HandleFunc("DELETE /v1/secrets/{path...}", h.handleDeleteSecret)

	return h.refuseUncleanSecretPaths(mux)
}

// refuseUncleanSecretPaths runs before the mux, which would otherwise redirect an
// unclean path and let a write land on a path the client never named.
func (h *Handlers) refuseUncleanSecretPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/secrets/") && path.Clean(r.URL.Path) != r.URL.Path {
			writeError(w, h.Logger, secret.ErrInvalidPath)
			return
		}
		next.ServeHTTP(w, r)
	})
}

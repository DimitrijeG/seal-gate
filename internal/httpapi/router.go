package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

// SystemService is the seal lifecycle as the handlers use it.
type SystemService interface {
	Init(ctx context.Context, cfg system.SealConfiguration) (system.InitResult, error)
	Unseal(ctx context.Context, share []byte) (system.Status, error)
	Seal(ctx context.Context)
}

// Handlers holds what the HTTP handlers call.
type Handlers struct {
	System SystemService
	Logger *slog.Logger
}

func NewRouter(h *Handlers) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/sys/init", h.handleInit)
	mux.HandleFunc("POST /v1/sys/unseal", h.handleUnseal)
	mux.HandleFunc("POST /v1/sys/seal", h.handleSeal)
	mux.HandleFunc("GET /v1/sys/status", h.handleStatus)
	mux.HandleFunc("GET /v1/sys/health", h.handleHealth)

	return mux
}

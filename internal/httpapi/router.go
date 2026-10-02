package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

type Handlers struct {
	System *system.Service
	Logger *slog.Logger
}

func NewRouter(h *Handlers) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("PUT /v1/sys/init", h.handleInit)
	mux.HandleFunc("GET /v1/sys/status", h.handleStatus)
	mux.HandleFunc("GET /v1/sys/health", h.handleHealth)
	mux.HandleFunc("PUT /v1/sys/seal", h.handleSeal)
	mux.HandleFunc("PUT /v1/sys/unseal", h.handleUnseal)

	return mux
}

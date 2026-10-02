package httpapi

import (
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

type initRequest struct {
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`
}

type initResponse struct {
	// Shown once and unrecoverable, so never logged or audited.
	// [][]byte because encoding/json already renders it as base64.
	Shares [][]byte `json:"shares"`
}

func (h *Handlers) handleInit(w http.ResponseWriter, r *http.Request) {
	var req initRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	result, err := h.System.Init(r.Context(), system.SealConfiguration{
		Shares:    req.Shares,
		Threshold: req.Threshold,
	})
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, initResponse{Shares: result.Shares})
}

func (h *Handlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleSeal(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleUnseal(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

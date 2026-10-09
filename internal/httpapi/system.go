package httpapi

import (
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

type initRequest struct {
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`
}

// initResponse carries the shares; []byte fields encode as base64.
type initResponse struct {
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
	// Deferred before the error check: cleared after the response is written, whatever Init returned.
	defer zeroShares(result.Shares)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, initResponse{
		Shares: result.Shares,
	})
}

type unsealRequest struct {
	Share []byte `json:"share"`
}

type statusResponse struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Shares      int  `json:"shares,omitempty"`
	Threshold   int  `json:"threshold,omitempty"`
	Progress    int  `json:"progress"`
}

func newStatusResponse(s system.Status) statusResponse {
	return statusResponse{
		Initialized: s.Initialized,
		Sealed:      s.Sealed,
		Shares:      s.Config.Shares,
		Threshold:   s.Config.Threshold,
		Progress:    s.Progress,
	}
}

func (h *Handlers) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var req unsealRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	result, err := h.System.Unseal(r.Context(), req.Share)
	// Deferred before the error check: a rejected share is still key material.
	defer clear(req.Share)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, newStatusResponse(result))
}

func (h *Handlers) handleSeal(w http.ResponseWriter, r *http.Request) {
	h.System.Seal(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	result, err := h.System.Status(r.Context())
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, newStatusResponse(result))
}

func (h *Handlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	result, err := h.System.Status(r.Context())
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}
	if result.Sealed {
		writeError(w, h.Logger, errSealed)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func zeroShares(shares [][]byte) {
	for _, s := range shares {
		clear(s)
	}
}

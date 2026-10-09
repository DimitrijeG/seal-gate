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
	Shares      int  `json:"shares"`
	Threshold   int  `json:"threshold"`
	Progress    int  `json:"progress"`
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

	writeJSON(w, http.StatusOK, statusResponse{
		Initialized: result.Initialized,
		Sealed:      result.Sealed,
		Shares:      result.Config.Shares,
		Threshold:   result.Config.Threshold,
		Progress:    result.Progress,
	})
}

func (h *Handlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleSeal(w http.ResponseWriter, r *http.Request) {
	h.System.Seal(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func zeroShares(shares [][]byte) {
	for _, s := range shares {
		clear(s)
	}
}

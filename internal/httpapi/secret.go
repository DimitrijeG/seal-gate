package httpapi

import (
	"encoding/base64"
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

// secretBodyLimit leaves room for the largest value in base64 plus the JSON around it.
var secretBodyLimit = int64(base64.StdEncoding.EncodedLen(secret.MaxValueSize) + 1<<10)

type secretRequest struct {
	Value []byte `json:"value"`
}

func (h *Handlers) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	var req secretRequest
	if err := decodeJSON(w, r, &req, secretBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	if err := h.Secret.Put(r.Context(), path, req.Value); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type secretResponse struct {
	Value []byte `json:"value"`
}

func (h *Handlers) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	value, err := h.Secret.Get(r.Context(), path)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	// A nil slice encodes as null; the spec's value is a string.
	if value == nil {
		value = []byte{}
	}

	writeJSON(w, http.StatusOK, secretResponse{
		Value: value,
	})
}

func (h *Handlers) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	if err := h.Secret.Delete(r.Context(), path); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

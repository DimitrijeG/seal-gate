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

	if err := h.Secret.Put(r.Context(), principalFrom(r), path, req.Value); err != nil {
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

	value, err := h.Secret.Get(r.Context(), principalFrom(r), path)
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

	if err := h.Secret.Delete(r.Context(), principalFrom(r), path); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// generateBodyLimit fits {"length": n} with room to spare; the body never carries a value.
const generateBodyLimit = 1 << 10

type generateRequest struct {
	Length int `json:"length"`
}

func (h *Handlers) handleGenerateSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	var req generateRequest
	if err := decodeJSON(w, r, &req, generateBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	value, err := h.Secret.Generate(r.Context(), principalFrom(r), path, req.Length)
	// Deferred before the error check: cleared after the response is written, whatever Generate returned.
	defer clear(value)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, secretResponse{Value: value})
}

type listResponse struct {
	Paths []string `json:"paths"`
}

func (h *Handlers) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")

	paths, err := h.Secret.List(r.Context(), principalFrom(r), prefix)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	// A nil slice encodes as null; the spec's paths is an array.
	if paths == nil {
		paths = []string{}
	}

	writeJSON(w, http.StatusOK, listResponse{
		Paths: paths,
	})
}

package httpapi

import (
	"encoding/base64"
	"math"
	"net/http"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

// maxTTLSeconds is the longest ttl a time.Duration holds; past it, seconds times time.Second wraps.
const maxTTLSeconds = math.MaxInt64 / int64(time.Second)

// ttlFrom converts a request's ttl in seconds, refusing it before multiplying when it is negative or too large to hold,
// since either can wrap into a valid-looking duration.
func ttlFrom(seconds int64) (time.Duration, error) {
	if seconds < 0 || seconds > maxTTLSeconds {
		return 0, errInvalidTTL
	}
	return time.Duration(seconds) * time.Second, nil
}

// secretBodyLimit leaves room for the largest value in base64 plus the JSON around it.
var secretBodyLimit = int64(base64.StdEncoding.EncodedLen(secret.MaxValueSize) + 1<<10)

type secretRequest struct {
	Value []byte `json:"value"`
	TTL   int64  `json:"ttl"`
}

func (h *Handlers) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	var req secretRequest
	if err := decodeJSON(w, r, &req, secretBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}
	// Deferred before any call: a refused value is still a secret.
	defer clear(req.Value)

	ttl, err := ttlFrom(req.TTL)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	if err := h.Secret.Put(r.Context(), principalFrom(r), path, req.Value, ttl); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type secretReadResponse struct {
	Value     []byte    `json:"value"`
	Generated bool      `json:"generated"`
	TTL       int64     `json:"ttl,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

func (h *Handlers) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	entry, err := h.Secret.Get(r.Context(), principalFrom(r), path)
	// Deferred before the error check: cleared after the response is written, whatever Get returned.
	defer clear(entry.Value)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	value := entry.Value
	// A nil slice encodes as null; the spec's value is a string.
	if value == nil {
		value = []byte{}
	}

	writeJSON(w, http.StatusOK, secretReadResponse{
		Value:     value,
		Generated: entry.Generated,
		TTL:       int64(entry.TTL / time.Second),
		// The real clock reads local time; the spec promises UTC.
		ExpiresAt: entry.ExpiresAt.UTC(),
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

// secretResponse is generate's and rotate's body; GET's always carries generated, so it has its own type.
type secretResponse struct {
	Value []byte `json:"value"`
}

// generateBodyLimit fits {"length": n} with room to spare; the body never carries a value.
const generateBodyLimit = 1 << 10

type generateRequest struct {
	Length int   `json:"length"`
	TTL    int64 `json:"ttl"`
}

func (h *Handlers) handleGenerateSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	var req generateRequest
	if err := decodeJSON(w, r, &req, generateBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	ttl, err := ttlFrom(req.TTL)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	value, err := h.Secret.Generate(r.Context(), principalFrom(r), path, req.Length, ttl)
	// Deferred before the error check: cleared after the response is written, whatever Generate returned.
	defer clear(value)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, secretResponse{Value: value})
}

func (h *Handlers) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	value, err := h.Secret.Rotate(r.Context(), principalFrom(r), path)
	// Deferred before the error check: cleared after the response is written, whatever Rotate returned.
	defer clear(value)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, secretResponse{Value: value})
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

	writeJSON(w, http.StatusOK, listResponse{
		Paths: orEmpty(paths),
	})
}

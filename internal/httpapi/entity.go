package httpapi

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// entityBodyLimit is the only cap on how many policies and groups an entity holds; identity bounds each one.
const entityBodyLimit = 64 << 10

type entityRequest struct {
	Policies []string `json:"policies"`
	Groups   []string `json:"groups"`
}

type entityResponse struct {
	Policies []string `json:"policies"`
	Groups   []string `json:"groups"`
}

type createEntityResponse struct {
	ID string `json:"id"`
}

func (h *Handlers) handleCreateEntity(w http.ResponseWriter, r *http.Request) {
	var req entityRequest
	if err := decodeJSON(w, r, &req, entityBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	id, err := h.Entity.CreateEntity(r.Context(), principalFrom(r), req.entity(""))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, createEntityResponse{ID: id})
}

func (h *Handlers) handleGetEntity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	entity, err := h.Entity.GetEntity(r.Context(), principalFrom(r), id)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, newEntityResponse(entity))
}

func (h *Handlers) handleUpdateEntity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req entityRequest
	if err := decodeJSON(w, r, &req, entityBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	if err := h.Entity.UpdateEntity(r.Context(), principalFrom(r), req.entity(id)); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleDeleteEntity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := h.Entity.DeleteEntity(r.Context(), principalFrom(r), id); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// createTokenResponse carries the token once; []byte encodes as base64.
type createTokenResponse struct {
	Token     []byte    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// tokenBodyLimit fits {"ttl": n} with room to spare.
const tokenBodyLimit = 1 << 10

type tokenRequest struct {
	TTL int64 `json:"ttl"`
}

// tokenTTL reads the optional token request body: a client that sends none gets the default TTL.
func tokenTTL(w http.ResponseWriter, r *http.Request) (time.Duration, error) {
	var req tokenRequest
	if !emptyBody(r) {
		if err := decodeJSON(w, r, &req, tokenBodyLimit); err != nil {
			return 0, err
		}
	}
	return ttlFrom(req.TTL)
}

// emptyBody reports whether r has no body; one of unknown length is peeked at and put back whole.
func emptyBody(r *http.Request) bool {
	if r.ContentLength != -1 {
		return r.ContentLength == 0
	}
	body := bufio.NewReader(r.Body)
	if _, err := body.Peek(1); errors.Is(err, io.EOF) {
		return true
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{body, r.Body}
	return false
}

func (h *Handlers) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	ttl, err := tokenTTL(w, r)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	token, expiresAt, err := h.Token.CreateToken(r.Context(), principalFrom(r), id, ttl)
	// Deferred before the error check: cleared after the response is written, whatever CreateToken returned.
	defer clear(token)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	// The spec promises UTC, whatever zone the clock reads.
	writeJSON(w, http.StatusCreated, createTokenResponse{Token: token, ExpiresAt: expiresAt.UTC()})
}

func (h *Handlers) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if err := h.Token.RevokeToken(r.Context(), tokenFrom(r)); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	ttl, err := tokenTTL(w, r)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	token, expiresAt, err := h.Token.RotateToken(r.Context(), tokenFrom(r), ttl)
	// Deferred before the error check: cleared after the response is written, whatever RotateToken returned.
	defer clear(token)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, createTokenResponse{Token: token, ExpiresAt: expiresAt.UTC()})
}

// entity takes id from the URL, or none on create, never from the body: IDs are generated, not chosen.
func (req entityRequest) entity(id string) identity.Entity {
	return identity.Entity{
		ID:       id,
		Policies: req.Policies,
		Groups:   req.Groups,
	}
}

// newEntityResponse leaves out the ID: the URL already holds it.
func newEntityResponse(entity identity.Entity) entityResponse {
	// make, not the domain slices, so an empty list encodes as [] rather than null.
	policies := make([]string, len(entity.Policies))
	copy(policies, entity.Policies)
	groups := make([]string, len(entity.Groups))
	copy(groups, entity.Groups)

	return entityResponse{Policies: policies, Groups: groups}
}

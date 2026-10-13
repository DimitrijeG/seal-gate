package httpapi

import (
	"net/http"

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

	id, err := h.Entity.CreateEntity(r.Context(), req.entity(""))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, createEntityResponse{ID: id})
}

func (h *Handlers) handleGetEntity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	entity, err := h.Entity.GetEntity(r.Context(), id)
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

	if err := h.Entity.UpdateEntity(r.Context(), req.entity(id)); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleDeleteEntity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := h.Entity.DeleteEntity(r.Context(), id); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// createTokenResponse carries the token once; []byte encodes as base64.
type createTokenResponse struct {
	Token []byte `json:"token"`
}

func (h *Handlers) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	token, err := h.Entity.CreateToken(r.Context(), id)
	// Deferred before the error check: cleared after the response is written, whatever CreateToken returned.
	defer clear(token)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, createTokenResponse{Token: token})
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

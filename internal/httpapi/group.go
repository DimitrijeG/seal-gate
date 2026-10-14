package httpapi

import (
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// groupBodyLimit is the only cap on how many policies a group holds; identity bounds each one.
const groupBodyLimit = 64 << 10

type groupRequest struct {
	Policies []string `json:"policies"`
}

type groupResponse struct {
	Policies []string `json:"policies"`
}

type createGroupResponse struct {
	ID string `json:"id"`
}

func (h *Handlers) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req groupRequest
	if err := decodeJSON(w, r, &req, groupBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	id, err := h.Group.CreateGroup(r.Context(), principalFrom(r), req.group(""))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, createGroupResponse{ID: id})
}

func (h *Handlers) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	group, err := h.Group.GetGroup(r.Context(), principalFrom(r), id)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, newGroupResponse(group))
}

func (h *Handlers) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req groupRequest
	if err := decodeJSON(w, r, &req, groupBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	if err := h.Group.UpdateGroup(r.Context(), principalFrom(r), req.group(id)); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := h.Group.DeleteGroup(r.Context(), principalFrom(r), id); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// group takes id from the URL, or none on create, never from the body: IDs are generated, not chosen.
func (req groupRequest) group(id string) identity.Group {
	return identity.Group{
		ID:       id,
		Policies: req.Policies,
	}
}

// newGroupResponse leaves out the ID: the URL already holds it.
func newGroupResponse(group identity.Group) groupResponse {
	// make, not the domain slice, so an empty list encodes as [] rather than null.
	policies := make([]string, len(group.Policies))
	copy(policies, group.Policies)

	return groupResponse{Policies: policies}
}

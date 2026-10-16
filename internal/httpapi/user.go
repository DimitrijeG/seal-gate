package httpapi

import "net/http"

// userBodyLimit fits the longest password identity accepts at six escaped bytes per byte, the most JSON needs, and an entity ID.
const userBodyLimit = 8 << 10

type userRequest struct {
	EntityID string `json:"entity_id"`
	Password string `json:"password"`
}

func (h *Handlers) handleSetUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req userRequest
	if err := decodeJSON(w, r, &req, userBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	if err := h.User.SetUser(r.Context(), principalFrom(r), name, req.EntityID, []byte(req.Password)); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := h.User.DeleteUser(r.Context(), principalFrom(r), name); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

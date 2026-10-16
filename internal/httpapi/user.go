package httpapi

import "net/http"

// userBodyLimit fits the longest password identity accepts at six escaped bytes per byte, the most JSON needs, and an entity ID or a username.
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

type userResponse struct {
	EntityID string `json:"entity_id"`
}

func (h *Handlers) handleGetUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	user, err := h.User.GetUser(r.Context(), principalFrom(r), name)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse{EntityID: user.EntityID})
}

func (h *Handlers) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := h.User.DeleteUser(r.Context(), principalFrom(r), name); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req, userBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	token, expiresAt, err := h.User.Login(r.Context(), req.Username, []byte(req.Password))
	// Deferred before the error check: cleared after the response is written, whatever Login returned.
	defer clear(token)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, createTokenResponse{Token: token, ExpiresAt: expiresAt.UTC()})
}

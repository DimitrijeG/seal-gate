package httpapi

import "net/http"

type namesResponse struct {
	Names []string `json:"names"`
}

type idsResponse struct {
	IDs []string `json:"ids"`
}

func (h *Handlers) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	names, err := h.Policy.List(r.Context(), principalFrom(r))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, namesResponse{Names: orEmpty(names)})
}

func (h *Handlers) handleListEntities(w http.ResponseWriter, r *http.Request) {
	ids, err := h.Entity.ListEntities(r.Context(), principalFrom(r))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, idsResponse{IDs: orEmpty(ids)})
}

func (h *Handlers) handleListGroups(w http.ResponseWriter, r *http.Request) {
	ids, err := h.Group.ListGroups(r.Context(), principalFrom(r))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, idsResponse{IDs: orEmpty(ids)})
}

func (h *Handlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	names, err := h.User.ListUsers(r.Context(), principalFrom(r))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, namesResponse{Names: orEmpty(names)})
}

// orEmpty returns list, or an empty slice for nil, which would encode as null where the spec has an array.
func orEmpty(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

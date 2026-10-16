package httpapi

import "net/http"

type namesResponse struct {
	Names []string `json:"names"`
}

type summaryResponse struct {
	ID    string `json:"id"`
	Alias string `json:"alias,omitempty"`
}

type entitiesResponse struct {
	Entities []summaryResponse `json:"entities"`
}

type groupsResponse struct {
	Groups []summaryResponse `json:"groups"`
}

type userSummaryResponse struct {
	Name     string `json:"name"`
	EntityID string `json:"entity_id"`
}

type usersResponse struct {
	Users []userSummaryResponse `json:"users"`
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
	entities, err := h.Entity.ListEntities(r.Context(), principalFrom(r))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	// make, not append onto nil, so an empty list encodes as [] rather than null.
	summaries := make([]summaryResponse, 0, len(entities))
	for _, entity := range entities {
		summaries = append(summaries, summaryResponse{ID: entity.ID, Alias: entity.Alias})
	}
	writeJSON(w, http.StatusOK, entitiesResponse{Entities: summaries})
}

func (h *Handlers) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.Group.ListGroups(r.Context(), principalFrom(r))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	summaries := make([]summaryResponse, 0, len(groups))
	for _, group := range groups {
		summaries = append(summaries, summaryResponse{ID: group.ID, Alias: group.Alias})
	}
	writeJSON(w, http.StatusOK, groupsResponse{Groups: summaries})
}

func (h *Handlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.User.ListUsers(r.Context(), principalFrom(r))
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	summaries := make([]userSummaryResponse, 0, len(users))
	for _, user := range users {
		summaries = append(summaries, userSummaryResponse{Name: user.Name, EntityID: user.EntityID})
	}
	writeJSON(w, http.StatusOK, usersResponse{Users: summaries})
}

// orEmpty returns list, or an empty slice for nil, which would encode as null where the spec has an array.
func orEmpty(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

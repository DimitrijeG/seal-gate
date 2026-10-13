package httpapi_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

const devGroupJSON = `{"policies":["dev"]}`

func TestGroup(t *testing.T) {
	t.Run("a created group reaches the service with its policies", func(t *testing.T) {
		fake := &fakeGroup{}
		router := httpapi.NewRouter(&httpapi.Handlers{Group: fake})
		want := identity.Group{Policies: []string{"dev"}}

		rec := do(t, router, http.MethodPost, "/v1/groups", devGroupJSON)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if !reflect.DeepEqual(fake.created, want) {
			t.Errorf("got %+v, want %+v", fake.created, want)
		}
	})

	t.Run("a create answers with the new ID", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{Group: &fakeGroup{createID: groupID}})

		rec := do(t, router, http.MethodPost, "/v1/groups", devGroupJSON)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		got := decode[createGroupBody](t, rec)

		if got.ID != groupID {
			t.Errorf("got %q, want %q", got.ID, groupID)
		}
	})

	t.Run("a body naming the ID is refused", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{Group: &fakeGroup{}})

		rec := do(t, router, http.MethodPost, "/v1/groups", `{"id":"`+groupID+`","policies":[]}`)

		assertError(t, rec, http.StatusBadRequest, `unknown field in request body: "id"`)
	})

	t.Run("an empty object creates a group without policies", func(t *testing.T) {
		fake := &fakeGroup{}
		router := httpapi.NewRouter(&httpapi.Handlers{Group: fake})

		rec := do(t, router, http.MethodPost, "/v1/groups", `{}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if len(fake.created.Policies) != 0 {
			t.Errorf("got %+v, want no policies", fake.created)
		}
	})

	t.Run("a stored group is returned with its policies", func(t *testing.T) {
		stored := identity.Group{ID: groupID, Policies: []string{"dev"}}
		router := httpapi.NewRouter(&httpapi.Handlers{Group: &fakeGroup{getGroup: stored}})
		want := groupBody{Policies: []string{"dev"}}

		rec := do(t, router, http.MethodGet, "/v1/groups/"+groupID, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[groupBody](t, rec)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a group without policies is returned with an empty list", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{Group: &fakeGroup{getGroup: identity.Group{ID: groupID}}})
		want := `{"policies":[]}`

		rec := do(t, router, http.MethodGet, "/v1/groups/"+groupID, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := strings.TrimSpace(rec.Body.String())

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("an update reaches the service with the ID from the URL", func(t *testing.T) {
		fake := &fakeGroup{}
		router := httpapi.NewRouter(&httpapi.Handlers{Group: fake})
		want := identity.Group{ID: groupID, Policies: []string{"dev"}}

		rec := do(t, router, http.MethodPut, "/v1/groups/"+groupID, devGroupJSON)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !reflect.DeepEqual(fake.updated, want) {
			t.Errorf("got %+v, want %+v", fake.updated, want)
		}
	})

	t.Run("a delete answers no content", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{Group: &fakeGroup{}})

		rec := do(t, router, http.MethodDelete, "/v1/groups/"+groupID, "")

		if rec.Code != http.StatusNoContent {
			t.Errorf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("body: got %q, want empty", rec.Body)
		}
	})

	t.Run("each operation passes the ID to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
		}{
			{"get", http.MethodGet},
			{"delete", http.MethodDelete},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeGroup{}
				router := httpapi.NewRouter(&httpapi.Handlers{Group: fake})

				do(t, router, tt.method, "/v1/groups/"+groupID, "")

				if fake.id != groupID {
					t.Errorf("got %q, want %q", fake.id, groupID)
				}
			})
		}
	})

	t.Run("each operation reports the service's error", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			path   string
			body   string
		}{
			{"create", http.MethodPost, "/v1/groups", devGroupJSON},
			{"get", http.MethodGet, "/v1/groups/" + groupID, ""},
			{"update", http.MethodPut, "/v1/groups/" + groupID, devGroupJSON},
			{"delete", http.MethodDelete, "/v1/groups/" + groupID, ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{Group: &fakeGroup{err: identity.ErrSealed}})

				rec := do(t, router, tt.method, tt.path, tt.body)

				assertError(t, rec, http.StatusServiceUnavailable, "the system is sealed")
			})
		}
	})

	t.Run("each domain error maps to its status and message", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"invalid group ID", identity.ErrInvalidGroupID, http.StatusBadRequest, "invalid group ID"},
			{"invalid policy name", identity.ErrInvalidPolicyName, http.StatusBadRequest, "invalid policy name"},
			{"not found", identity.ErrGroupNotFound, http.StatusNotFound, "group not found"},
			// A corrupt record is the server's fault, not the client's.
			{"unreadable group", identity.ErrUnreadableGroup, http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{Group: &fakeGroup{err: tt.err}})

				rec := do(t, router, http.MethodGet, "/v1/groups/"+groupID, "")

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})
}

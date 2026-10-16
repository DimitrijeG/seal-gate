package httpapi_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// listRoute builds handlers whose service lists two items when full, none otherwise, or fails with err, and returns
// where its fake records the principal; body is what the full list encodes to.
type listRoute struct {
	name     string
	path     string
	field    string
	body     string
	handlers func(full bool, err error) (*httpapi.Handlers, *authorization.Principal)
}

var listRoutes = []listRoute{
	{"policies", "/v1/policies", "names", `{"names":["a","b"]}`, func(full bool, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakePolicy{err: err}
		if full {
			fake.list = []string{"a", "b"}
		}
		return &httpapi.Handlers{Policy: fake}, &fake.principal
	}},
	{"entities", "/v1/entities", "entities", `{"entities":[{"id":"` + entityID + `","alias":"ci"},{"id":"` + groupID + `"}]}`, func(full bool, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakeEntity{err: err}
		if full {
			fake.list = []identity.EntitySummary{{ID: entityID, Alias: "ci"}, {ID: groupID}}
		}
		return &httpapi.Handlers{Entity: fake}, &fake.principal
	}},
	{"groups", "/v1/groups", "groups", `{"groups":[{"id":"` + groupID + `","alias":"ops"},{"id":"` + entityID + `"}]}`, func(full bool, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakeGroup{err: err}
		if full {
			fake.list = []identity.GroupSummary{{ID: groupID, Alias: "ops"}, {ID: entityID}}
		}
		return &httpapi.Handlers{Group: fake}, &fake.principal
	}},
	{"users", "/v1/auth/users", "users", `{"users":[{"name":"alice","entity_id":"` + entityID + `"},{"name":"bob","entity_id":"` + groupID + `"}]}`, func(full bool, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakeUser{err: err}
		if full {
			fake.list = []identity.UserSummary{{Name: "alice", EntityID: entityID}, {Name: "bob", EntityID: groupID}}
		}
		return &httpapi.Handlers{User: fake}, &fake.principal
	}},
}

func TestListing(t *testing.T) {
	t.Run("a listing returns the service's list under its field", func(t *testing.T) {
		for _, route := range listRoutes {
			t.Run(route.name, func(t *testing.T) {
				h, _ := route.handlers(true, nil)
				h.Authenticator = &fakeAuthenticator{}
				want := route.body

				rec := do(t, newRouter(h), http.MethodGet, route.path, "")
				if rec.Code != http.StatusOK {
					t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
				}
				got := strings.TrimSpace(rec.Body.String())

				if got != want {
					t.Errorf("got %q, want %q", got, want)
				}
			})
		}
	})

	t.Run("an empty listing is an empty array", func(t *testing.T) {
		for _, route := range listRoutes {
			t.Run(route.name, func(t *testing.T) {
				h, _ := route.handlers(false, nil)
				h.Authenticator = &fakeAuthenticator{}
				want := `{"` + route.field + `":[]}`

				rec := do(t, newRouter(h), http.MethodGet, route.path, "")
				if rec.Code != http.StatusOK {
					t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
				}
				got := strings.TrimSpace(rec.Body.String())

				if got != want {
					t.Errorf("got %q, want %q", got, want)
				}
			})
		}
	})

	t.Run("a listing passes the authenticated principal to the service", func(t *testing.T) {
		want := authorization.NewEntityPrincipal(entityID, "admin")
		for _, route := range listRoutes {
			t.Run(route.name, func(t *testing.T) {
				h, principal := route.handlers(false, nil)
				h.Authenticator = &fakeAuthenticator{principal: want}

				do(t, newRouter(h), http.MethodGet, route.path, "")

				if !reflect.DeepEqual(*principal, want) {
					t.Errorf("got %+v, want %+v", *principal, want)
				}
			})
		}
	})

	t.Run("a denied listing is forbidden", func(t *testing.T) {
		for _, route := range listRoutes {
			t.Run(route.name, func(t *testing.T) {
				h, _ := route.handlers(false, authorization.ErrDenied)
				h.Authenticator = &fakeAuthenticator{}

				rec := do(t, newRouter(h), http.MethodGet, route.path, "")

				assertError(t, rec, http.StatusForbidden, "permission denied")
			})
		}
	})
}

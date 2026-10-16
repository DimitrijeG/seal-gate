package httpapi_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
)

// listRoute builds handlers whose service lists list or fails with err, and returns where its fake records the principal.
type listRoute struct {
	name     string
	path     string
	field    string
	handlers func(list []string, err error) (*httpapi.Handlers, *authorization.Principal)
}

var listRoutes = []listRoute{
	{"policies", "/v1/policies", "names", func(list []string, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakePolicy{list: list, err: err}
		return &httpapi.Handlers{Policy: fake}, &fake.principal
	}},
	{"entities", "/v1/entities", "ids", func(list []string, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakeEntity{list: list, err: err}
		return &httpapi.Handlers{Entity: fake}, &fake.principal
	}},
	{"groups", "/v1/groups", "ids", func(list []string, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakeGroup{list: list, err: err}
		return &httpapi.Handlers{Group: fake}, &fake.principal
	}},
	{"users", "/v1/auth/users", "names", func(list []string, err error) (*httpapi.Handlers, *authorization.Principal) {
		fake := &fakeUser{list: list, err: err}
		return &httpapi.Handlers{User: fake}, &fake.principal
	}},
}

func TestListing(t *testing.T) {
	t.Run("a listing returns the service's list under its field", func(t *testing.T) {
		for _, route := range listRoutes {
			t.Run(route.name, func(t *testing.T) {
				h, _ := route.handlers([]string{"a", "b"}, nil)
				h.Authenticator = &fakeAuthenticator{}
				want := `{"` + route.field + `":["a","b"]}`

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
				h, _ := route.handlers(nil, nil)
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
				h, principal := route.handlers(nil, nil)
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
				h, _ := route.handlers(nil, authorization.ErrDenied)
				h.Authenticator = &fakeAuthenticator{}

				rec := do(t, newRouter(h), http.MethodGet, route.path, "")

				assertError(t, rec, http.StatusForbidden, "permission denied")
			})
		}
	})
}

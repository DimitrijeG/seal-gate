package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
)

func TestRouter(t *testing.T) {
	t.Run("an endpoint with a body refuses what the decoder rejects", func(t *testing.T) {
		routes := []struct{ name, method, path string }{
			{"init", http.MethodPost, "/v1/sys/init"},
			{"unseal", http.MethodPost, "/v1/sys/unseal"},
			{"put secret", http.MethodPut, "/v1/secrets/db/password"},
			{"put policy", http.MethodPut, "/v1/policies/dev"},
			{"create entity", http.MethodPost, "/v1/entities"},
			{"update entity", http.MethodPut, "/v1/entities/" + entityID},
			{"create group", http.MethodPost, "/v1/groups"},
			{"update group", http.MethodPut, "/v1/groups/" + groupID},
		}
		// Bodies fit no endpoint in particular, so each case applies to every route.
		tests := []struct {
			name        string
			contentType string
			body        string
			status      int
			message     string
		}{
			{"wrong content type", "text/plain", `{}`, http.StatusUnsupportedMediaType, "expected Content-Type application/json"},
			{"unknown field", contentTypeJSON, `{"nope":1}`, http.StatusBadRequest, `unknown field in request body: "nope"`},
		}

		for _, route := range routes {
			for _, tt := range tests {
				t.Run(route.name+" "+tt.name, func(t *testing.T) {
					req := httptest.NewRequest(route.method, route.path, strings.NewReader(tt.body))
					req.Header.Set("Content-Type", tt.contentType)
					req.Header.Set("Authorization", bearer)
					rec := httptest.NewRecorder()
					router := newRouter(&httpapi.Handlers{
						Authenticator: &fakeAuthenticator{},
						System:        &fakeSystem{},
						Secret:        &fakeSecret{},
						Policy:        &fakePolicy{},
						Entity:        &fakeEntity{},
					})

					router.ServeHTTP(rec, req)

					assertError(t, rec, tt.status, tt.message)
				})
			}
		}
	})

	t.Run("an endpoint refuses a body over its limit", func(t *testing.T) {
		routes := []struct {
			name, method, path string
			limit              int
		}{
			{"init", http.MethodPost, "/v1/sys/init", 16384},
			{"unseal", http.MethodPost, "/v1/sys/unseal", 16384},
			{"put secret", http.MethodPut, "/v1/secrets/db/password", 88408},
			{"put policy", http.MethodPut, "/v1/policies/dev", 65536},
			{"create entity", http.MethodPost, "/v1/entities", 65536},
			{"update entity", http.MethodPut, "/v1/entities/" + entityID, 65536},
			{"create group", http.MethodPost, "/v1/groups", 65536},
			{"update group", http.MethodPut, "/v1/groups/" + groupID, 65536},
		}

		for _, route := range routes {
			t.Run(route.name, func(t *testing.T) {
				body := `{}` + strings.Repeat(" ", route.limit)
				want := fmt.Sprintf("request body exceeds %d bytes", route.limit)
				router := newRouter(&httpapi.Handlers{
					Authenticator: &fakeAuthenticator{},
					System:        &fakeSystem{},
					Secret:        &fakeSecret{},
					Policy:        &fakePolicy{},
					Entity:        &fakeEntity{},
					Group:         &fakeGroup{},
				})

				rec := do(t, router, route.method, route.path, body)

				assertError(t, rec, http.StatusRequestEntityTooLarge, want)
			})
		}
	})

	t.Run("an action path that is not in its clean form is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment under generate", "/v1/secrets/generate/db/../password"},
			{"current segment under generate", "/v1/secrets/generate/db/./password"},
			{"empty segment under generate", "/v1/secrets/generate/db//password"},
			{"parent segment up to the generate route", "/v1/secrets/generate/.."},
			{"parent segment under rotate", "/v1/secrets/rotate/db/../password"},
			{"current segment under rotate", "/v1/secrets/rotate/db/./password"},
			{"empty segment under rotate", "/v1/secrets/rotate/db//password"},
			{"parent segment up to the rotate route", "/v1/secrets/rotate/.."},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{}})

				rec := do(t, router, http.MethodPost, tt.target, `{"length":32}`)

				assertError(t, rec, http.StatusBadRequest, "invalid secret path")
			})
		}
	})

	t.Run("a secret path that is not in its clean form is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/secrets/db/../password"},
			{"current segment", "/v1/secrets/db/./password"},
			{"empty segment", "/v1/secrets/db//password"},
			{"empty segment before the route", "/v1//secrets/db/password"},
			{"parent segment up to the collection", "/v1/secrets/db/.."},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{}})

				rec := do(t, router, http.MethodGet, tt.target, "")

				assertError(t, rec, http.StatusBadRequest, "invalid secret path")
			})
		}
	})

	t.Run("a policy path that is not in its clean form is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/policies/dev/../admin"},
			{"current segment", "/v1/policies/./dev"},
			{"empty segment", "/v1/policies//dev"},
			{"empty segment before the route", "/v1//policies/dev"},
			{"empty segment before the version", "//v1/policies/dev"},
			{"parent segment from another route", "/v1/secrets/../policies/dev"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{}})

				rec := do(t, router, http.MethodPut, tt.target, devPolicyJSON)

				assertError(t, rec, http.StatusBadRequest, "invalid policy name")
			})
		}
	})

	t.Run("an entity path that is not in its clean form is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/entities/x/../" + entityID},
			{"current segment", "/v1/entities/./" + entityID},
			{"empty segment", "/v1/entities//" + entityID},
			{"empty segment before the route", "/v1//entities/" + entityID},
			{"empty segment before the version", "//v1/entities/" + entityID},
			{"parent segment from another route", "/v1/secrets/../entities/" + entityID},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{}})

				rec := do(t, router, http.MethodPut, tt.target, devEntityJSON)

				assertError(t, rec, http.StatusBadRequest, "invalid entity ID")
			})
		}
	})

	t.Run("an unclean path that cleans to the entity collection is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/entities/" + entityID + "/.."},
			{"empty segment before the route", "/v1//entities"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{}})

				rec := do(t, router, http.MethodPost, tt.target, devEntityJSON)

				assertError(t, rec, http.StatusBadRequest, "invalid entity ID")
			})
		}
	})

	t.Run("a group path that is not in its clean form is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/groups/x/../" + groupID},
			{"current segment", "/v1/groups/./" + groupID},
			{"empty segment", "/v1/groups//" + groupID},
			{"empty segment before the route", "/v1//groups/" + groupID},
			{"empty segment before the version", "//v1/groups/" + groupID},
			{"parent segment from another route", "/v1/secrets/../groups/" + groupID},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Group: &fakeGroup{}})

				rec := do(t, router, http.MethodPut, tt.target, devGroupJSON)

				assertError(t, rec, http.StatusBadRequest, "invalid group ID")
			})
		}
	})

	t.Run("an unclean path that cleans to the group collection is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/groups/" + groupID + "/.."},
			{"empty segment before the route", "/v1//groups"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Group: &fakeGroup{}})

				rec := do(t, router, http.MethodPost, tt.target, devGroupJSON)

				assertError(t, rec, http.StatusBadRequest, "invalid group ID")
			})
		}
	})

	t.Run("a token path that is not in its clean form is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/entities/x/../" + entityID + "/tokens"},
			{"current segment", "/v1/entities/" + entityID + "/./tokens"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{}})

				rec := do(t, router, http.MethodPost, tt.target, "")

				assertError(t, rec, http.StatusBadRequest, "invalid entity ID")
			})
		}
	})
}

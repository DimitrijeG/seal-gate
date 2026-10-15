package httpapi_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

const (
	entityID      = "0123456789abcdef0123456789abcdef"
	groupID       = "fedcba9876543210fedcba9876543210"
	devEntityJSON = `{"policies":["dev"],"groups":["` + groupID + `"]}`
)

func TestEntity(t *testing.T) {
	t.Run("a created entity reaches the service with its policies and groups", func(t *testing.T) {
		fake := &fakeEntity{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: fake})
		want := identity.Entity{Policies: []string{"dev"}, Groups: []string{groupID}}

		rec := do(t, router, http.MethodPost, "/v1/entities", devEntityJSON)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if !reflect.DeepEqual(fake.created, want) {
			t.Errorf("got %+v, want %+v", fake.created, want)
		}
	})

	t.Run("a create answers with the new ID", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{createID: entityID}})

		rec := do(t, router, http.MethodPost, "/v1/entities", devEntityJSON)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		got := decode[createEntityBody](t, rec)

		if got.ID != entityID {
			t.Errorf("got %q, want %q", got.ID, entityID)
		}
	})

	t.Run("a body naming the ID is refused", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{}})

		rec := do(t, router, http.MethodPost, "/v1/entities", `{"id":"`+entityID+`","policies":[]}`)

		assertError(t, rec, http.StatusBadRequest, `unknown field in request body: "id"`)
	})

	t.Run("an empty object creates an entity without policies or groups", func(t *testing.T) {
		fake := &fakeEntity{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: fake})

		rec := do(t, router, http.MethodPost, "/v1/entities", `{}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if len(fake.created.Policies) != 0 || len(fake.created.Groups) != 0 {
			t.Errorf("got %+v, want no policies or groups", fake.created)
		}
	})

	t.Run("a stored entity is returned with its policies and groups", func(t *testing.T) {
		stored := identity.Entity{ID: entityID, Policies: []string{"dev"}, Groups: []string{groupID}}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{getEntity: stored}})
		want := entityBody{Policies: []string{"dev"}, Groups: []string{groupID}}

		rec := do(t, router, http.MethodGet, "/v1/entities/"+entityID, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[entityBody](t, rec)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("an entity without policies or groups is returned with empty lists", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{getEntity: identity.Entity{ID: entityID}}})
		want := `{"policies":[],"groups":[]}`

		rec := do(t, router, http.MethodGet, "/v1/entities/"+entityID, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := strings.TrimSpace(rec.Body.String())

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("an update reaches the service with the ID from the URL", func(t *testing.T) {
		fake := &fakeEntity{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: fake})
		want := identity.Entity{ID: entityID, Policies: []string{"dev"}, Groups: []string{groupID}}

		rec := do(t, router, http.MethodPut, "/v1/entities/"+entityID, devEntityJSON)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !reflect.DeepEqual(fake.updated, want) {
			t.Errorf("got %+v, want %+v", fake.updated, want)
		}
	})

	t.Run("a delete answers no content", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{}})

		rec := do(t, router, http.MethodDelete, "/v1/entities/"+entityID, "")

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
				fake := &fakeEntity{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: fake})

				do(t, router, tt.method, "/v1/entities/"+entityID, "")

				if fake.id != entityID {
					t.Errorf("got %q, want %q", fake.id, entityID)
				}
			})
		}
	})

	t.Run("each operation passes the authenticated principal to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			path   string
			body   string
			got    func(e *fakeEntity, k *fakeToken) authorization.Principal
		}{
			{"get", http.MethodGet, "/v1/entities/" + entityID, "", func(e *fakeEntity, _ *fakeToken) authorization.Principal {
				return e.principal
			}},
			{"create", http.MethodPost, "/v1/entities", devEntityJSON, func(e *fakeEntity, _ *fakeToken) authorization.Principal {
				return e.principal
			}},
			{"update", http.MethodPut, "/v1/entities/" + entityID, devEntityJSON, func(e *fakeEntity, _ *fakeToken) authorization.Principal {
				return e.principal
			}},
			{"delete", http.MethodDelete, "/v1/entities/" + entityID, "", func(e *fakeEntity, _ *fakeToken) authorization.Principal {
				return e.principal
			}},
			{"issue token", http.MethodPost, "/v1/entities/" + entityID + "/tokens", "", func(_ *fakeEntity, k *fakeToken) authorization.Principal {
				return k.principal
			}},
		}

		want := authorization.NewEntityPrincipal(entityID, "dev")
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				entity, token := &fakeEntity{}, &fakeToken{token: make([]byte, 32)}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{principal: want}, Entity: entity, Token: token})

				do(t, router, tt.method, tt.path, tt.body)

				if got := tt.got(entity, token); !reflect.DeepEqual(got, want) {
					t.Errorf("got %+v, want %+v", got, want)
				}
			})
		}
	})

	t.Run("a denied operation is forbidden", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{err: authorization.ErrDenied}})

		rec := do(t, router, http.MethodGet, "/v1/entities/"+entityID, "")

		assertError(t, rec, http.StatusForbidden, "permission denied")
	})

	t.Run("each operation reports the service's error", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			path   string
			body   string
		}{
			{"create", http.MethodPost, "/v1/entities", devEntityJSON},
			{"get", http.MethodGet, "/v1/entities/" + entityID, ""},
			{"update", http.MethodPut, "/v1/entities/" + entityID, devEntityJSON},
			{"delete", http.MethodDelete, "/v1/entities/" + entityID, ""},
			{"issue token", http.MethodPost, "/v1/entities/" + entityID + "/tokens", ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{
					Authenticator: &fakeAuthenticator{},
					Entity:        &fakeEntity{err: identity.ErrSealed},
					Token:         &fakeToken{err: identity.ErrSealed},
				})

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
			{"invalid entity ID", identity.ErrInvalidEntityID, http.StatusBadRequest, "invalid entity ID"},
			{"invalid policy name", identity.ErrInvalidPolicyName, http.StatusBadRequest, "invalid policy name"},
			{"invalid group ID", identity.ErrInvalidGroupID, http.StatusBadRequest, "invalid group ID"},
			{"not found", identity.ErrEntityNotFound, http.StatusNotFound, "entity not found"},
			// A corrupt record is the server's fault, not the client's.
			{"unreadable entity", identity.ErrUnreadableEntity, http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Entity: &fakeEntity{err: tt.err}})

				rec := do(t, router, http.MethodGet, "/v1/entities/"+entityID, "")

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("an issued token is returned in base64", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{token: bytes.Repeat([]byte{0xab}, 32)}})
		// A copy: the handler clears the fake's slice once the response is written.
		want := bytes.Repeat([]byte{0xab}, 32)

		rec := do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		got, err := base64.StdEncoding.DecodeString(decode[tokenBody](t, rec).Token)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("an issued token's expiry is returned in UTC", func(t *testing.T) {
		expiresAt := time.Date(2026, 10, 1, 15, 30, 0, 0, time.FixedZone("CEST", 2*60*60))
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{token: make([]byte, 32), expiresAt: expiresAt}})
		want := "2026-10-01T13:30:00Z"

		rec := do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if got := decode[tokenBody](t, rec).ExpiresAt; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a token request without a body gets the default TTL", func(t *testing.T) {
		// Set, so a handler that ignores the body cannot pass by leaving it at zero.
		fake := &fakeToken{token: make([]byte, 32), ttl: time.Minute}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})

		rec := do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if fake.ttl != 0 {
			t.Errorf("got %v, want 0", fake.ttl)
		}
	})

	t.Run("a ttl in the body reaches the service in seconds", func(t *testing.T) {
		fake := &fakeToken{token: make([]byte, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})
		want := 2 * time.Hour

		rec := do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", `{"ttl":7200}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if fake.ttl != want {
			t.Errorf("got %v, want %v", fake.ttl, want)
		}
	})

	t.Run("a refused ttl is 400", func(t *testing.T) {
		tests := []struct {
			name string
			body string
			err  error
		}{
			{"negative", `{"ttl":-1}`, nil},
			{"too large to hold", `{"ttl":9223372037}`, nil},
			{"above the maximum", `{"ttl":7200}`, identity.ErrInvalidTTL},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{err: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", tt.body)

				assertError(t, rec, http.StatusBadRequest, "invalid TTL")
			})
		}
	})

	t.Run("a token is issued for the entity in the URL", func(t *testing.T) {
		fake := &fakeToken{token: make([]byte, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})

		do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")

		if fake.entityID != entityID {
			t.Errorf("got %q, want %q", fake.entityID, entityID)
		}
	})

	t.Run("an issued token is cleared after the response is written", func(t *testing.T) {
		fake := &fakeToken{token: bytes.Repeat([]byte{0xab}, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})
		want := make([]byte, 32)

		rec := do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if !bytes.Equal(fake.token, want) {
			t.Errorf("got %x, want %x", fake.token, want)
		}
	})

	t.Run("revoking returns 204", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{}})

		rec := do(t, router, http.MethodPost, "/v1/auth/token/revoke", "")

		if rec.Code != http.StatusNoContent {
			t.Errorf("got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
	})

	t.Run("the presented token is the one revoked", func(t *testing.T) {
		fake := &fakeToken{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})
		want := []byte{1, 2, 3}

		rec := do(t, router, http.MethodPost, "/v1/auth/token/revoke", "")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !bytes.Equal(fake.revoked, want) {
			t.Errorf("got %x, want %x", fake.revoked, want)
		}
	})

	t.Run("the root token cannot be revoked", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{err: identity.ErrRootToken}})

		rec := do(t, router, http.MethodPost, "/v1/auth/token/revoke", "")

		assertError(t, rec, http.StatusBadRequest, "the root token cannot be revoked or rotated")
	})

	t.Run("rotating returns 201 with the new token", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{token: bytes.Repeat([]byte{0xab}, 32)}})
		// A copy: the handler clears the fake's slice once the response is written.
		want := bytes.Repeat([]byte{0xab}, 32)

		rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		got, err := base64.StdEncoding.DecodeString(decode[tokenBody](t, rec).Token)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("a rotated token's expiry is returned in UTC", func(t *testing.T) {
		expiresAt := time.Date(2026, 10, 1, 15, 30, 0, 0, time.FixedZone("CEST", 2*60*60))
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{token: make([]byte, 32), expiresAt: expiresAt}})
		want := "2026-10-01T13:30:00Z"

		rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if got := decode[tokenBody](t, rec).ExpiresAt; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("the presented token is the one rotated", func(t *testing.T) {
		fake := &fakeToken{token: make([]byte, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})
		want := []byte{1, 2, 3}

		rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if !bytes.Equal(fake.rotated, want) {
			t.Errorf("got %x, want %x", fake.rotated, want)
		}
	})

	t.Run("a ttl in the rotate body reaches the service in seconds", func(t *testing.T) {
		fake := &fakeToken{token: make([]byte, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})
		want := 2 * time.Hour

		rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", `{"ttl":7200}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if fake.ttl != want {
			t.Errorf("got %v, want %v", fake.ttl, want)
		}
	})

	t.Run("a rotate request without a body gets the default TTL", func(t *testing.T) {
		// Set, so a handler that ignores the body cannot pass by leaving it at zero.
		fake := &fakeToken{token: make([]byte, 32), ttl: time.Minute}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})

		rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if fake.ttl != 0 {
			t.Errorf("got %v, want 0", fake.ttl)
		}
	})

	t.Run("a refused rotate ttl is 400", func(t *testing.T) {
		tests := []struct {
			name string
			body string
			err  error
		}{
			{"negative", `{"ttl":-1}`, nil},
			{"too large to hold", `{"ttl":9223372037}`, nil},
			{"above the maximum", `{"ttl":7200}`, identity.ErrInvalidTTL},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{err: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", tt.body)

				assertError(t, rec, http.StatusBadRequest, "invalid TTL")
			})
		}
	})

	t.Run("the root token cannot be rotated", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{err: identity.ErrRootToken}})

		rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", "")

		assertError(t, rec, http.StatusBadRequest, "the root token cannot be revoked or rotated")
	})

	t.Run("a rotated token is cleared after the response is written", func(t *testing.T) {
		fake := &fakeToken{token: bytes.Repeat([]byte{0xab}, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: fake})
		want := make([]byte, 32)

		rec := do(t, router, http.MethodPost, "/v1/auth/token/rotate", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if !bytes.Equal(fake.token, want) {
			t.Errorf("got %x, want %x", fake.token, want)
		}
	})

	t.Run("an issued token forbids caching", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Token: &fakeToken{token: make([]byte, 32)}})
		want := "no-store"

		rec := do(t, router, http.MethodPost, "/v1/entities/"+entityID+"/tokens", "")

		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

package httpapi_test

import (
	"bytes"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// The space makes it invalid base64, so it arrives only if taken as typed.
const alicePassword = "correct horse"

const aliceJSON = `{"entity_id":"` + entityID + `","password":"` + alicePassword + `"}`

func TestUser(t *testing.T) {
	t.Run("a set user reaches the service with its name, entity ID and password", func(t *testing.T) {
		fake := &fakeUser{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: fake})

		rec := do(t, router, http.MethodPut, "/v1/auth/users/alice", aliceJSON)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if fake.name != "alice" {
			t.Errorf("name: got %q, want %q", fake.name, "alice")
		}
		if fake.entityID != entityID {
			t.Errorf("entity ID: got %q, want %q", fake.entityID, entityID)
		}
		if fake.password != alicePassword {
			t.Errorf("password: got %q, want %q", fake.password, alicePassword)
		}
	})

	t.Run("a stored user is returned as its entity ID", func(t *testing.T) {
		fake := &fakeUser{getUser: identity.UserSummary{Name: "alice", EntityID: entityID}}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: fake})
		want := `{"entity_id":"` + entityID + `"}`

		rec := do(t, router, http.MethodGet, "/v1/auth/users/alice", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := strings.TrimSpace(rec.Body.String())

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a delete answers no content", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: &fakeUser{}})

		rec := do(t, router, http.MethodDelete, "/v1/auth/users/alice", "")

		if rec.Code != http.StatusNoContent {
			t.Errorf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("body: got %q, want empty", rec.Body)
		}
	})

	t.Run("each operation passes the name to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
		}{
			{"get", http.MethodGet},
			{"delete", http.MethodDelete},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeUser{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: fake})

				do(t, router, tt.method, "/v1/auth/users/alice", "")

				if fake.name != "alice" {
					t.Errorf("got %q, want %q", fake.name, "alice")
				}
			})
		}
	})

	t.Run("each operation passes the authenticated principal to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			body   string
		}{
			{"set", http.MethodPut, aliceJSON},
			{"get", http.MethodGet, ""},
			{"delete", http.MethodDelete, ""},
		}

		want := authorization.NewEntityPrincipal(entityID, "admin")
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeUser{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{principal: want}, User: fake})

				do(t, router, tt.method, "/v1/auth/users/alice", tt.body)

				if !reflect.DeepEqual(fake.principal, want) {
					t.Errorf("got %+v, want %+v", fake.principal, want)
				}
			})
		}
	})

	t.Run("each operation reports the service's error", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			body   string
		}{
			{"set", http.MethodPut, aliceJSON},
			{"get", http.MethodGet, ""},
			{"delete", http.MethodDelete, ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: &fakeUser{err: identity.ErrSealed}})

				rec := do(t, router, tt.method, "/v1/auth/users/alice", tt.body)

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
			{"invalid username", identity.ErrInvalidUsername, http.StatusBadRequest, "invalid username"},
			{"invalid password", identity.ErrInvalidPassword, http.StatusBadRequest, "invalid password"},
			{"user not found", identity.ErrUserNotFound, http.StatusNotFound, "user not found"},
			// A corrupt record is the server's fault, not the client's.
			{"unreadable user", identity.ErrUnreadableUser, http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: &fakeUser{err: tt.err}})

				rec := do(t, router, http.MethodPut, "/v1/auth/users/alice", aliceJSON)

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})
}

const aliceLoginJSON = `{"username":"alice","password":"` + alicePassword + `"}`

func TestLogin(t *testing.T) {
	t.Run("logging in returns 201 with the token and its expiry", func(t *testing.T) {
		expiresAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		fake := &fakeUser{loginToken: []byte{0xab, 0xcd}, loginExpiresAt: expiresAt}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: fake})
		want := tokenBody{Token: "q80=", ExpiresAt: "2026-01-02T03:04:05Z"}

		rec := do(t, router, http.MethodPost, "/v1/auth/login", aliceLoginJSON)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if got := decode[tokenBody](t, rec); got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the username and password reach the service", func(t *testing.T) {
		fake := &fakeUser{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: fake})

		do(t, router, http.MethodPost, "/v1/auth/login", aliceLoginJSON)

		if fake.name != "alice" {
			t.Errorf("username: got %q, want %q", fake.name, "alice")
		}
		if fake.password != alicePassword {
			t.Errorf("password: got %q, want %q", fake.password, alicePassword)
		}
	})

	t.Run("the service's error is reported", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: &fakeUser{err: identity.ErrSealed}})

		rec := do(t, router, http.MethodPost, "/v1/auth/login", aliceLoginJSON)

		assertError(t, rec, http.StatusServiceUnavailable, "the system is sealed")
	})

	t.Run("each domain error maps to its status and message", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"invalid credentials", identity.ErrInvalidCredentials, http.StatusUnauthorized, "invalid username or password"},
			// A corrupt record is the server's fault, not the client's.
			{"unreadable user", identity.ErrUnreadableUser, http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: &fakeUser{err: tt.err}})

				rec := do(t, router, http.MethodPost, "/v1/auth/login", aliceLoginJSON)

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("the token is cleared after the response is written", func(t *testing.T) {
		fake := &fakeUser{loginToken: bytes.Repeat([]byte{0xab}, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, User: fake})
		want := make([]byte, 32)

		rec := do(t, router, http.MethodPost, "/v1/auth/login", aliceLoginJSON)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if !bytes.Equal(fake.loginToken, want) {
			t.Errorf("got %x, want %x", fake.loginToken, want)
		}
	})
}

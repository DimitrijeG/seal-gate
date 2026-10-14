package httpapi_test

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

func TestAuthentication(t *testing.T) {
	t.Run("a request with no authorization header is unauthorized", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{}})

		rec := doWithAuthorization(t, router, "", http.MethodGet, "/v1/secrets/db/password", "")

		assertError(t, rec, http.StatusUnauthorized, "missing or invalid token")
	})

	t.Run("an open route is reached without an authorization header", func(t *testing.T) {
		tests := []struct {
			name, method, path, body string
			status                   int
		}{
			{"init", http.MethodPost, "/v1/sys/init", `{"shares":2,"threshold":2}`, http.StatusOK},
			{"unseal", http.MethodPost, "/v1/sys/unseal", `{"share":"AQI="}`, http.StatusOK},
			{"status", http.MethodGet, "/v1/sys/status", "", http.StatusOK},
			{"health", http.MethodGet, "/v1/sys/health", "", http.StatusNoContent},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, System: &fakeSystem{}})

				rec := doWithAuthorization(t, router, "", tt.method, tt.path, tt.body)

				if rec.Code != tt.status {
					t.Errorf("got %d, want %d: %s", rec.Code, tt.status, rec.Body)
				}
			})
		}
	})

	t.Run("a malformed authorization header is unauthorized", func(t *testing.T) {
		tests := []struct{ name, authorization string }{
			{"wrong scheme", "Basic AQID"},
			{"bad base64", "Bearer !!!"},
			{"empty token", "Bearer "},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{}})

				rec := doWithAuthorization(t, router, tt.authorization, http.MethodGet, "/v1/secrets/db/password", "")

				assertError(t, rec, http.StatusUnauthorized, "missing or invalid token")
			})
		}
	})

	t.Run("a token the authenticator rejects is unauthorized", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{
			Authenticator: &fakeAuthenticator{err: identity.ErrInvalidToken},
			Secret:        &fakeSecret{},
		})

		rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")

		assertError(t, rec, http.StatusUnauthorized, "missing or invalid token")
	})

	t.Run("the authenticator gets the decoded token", func(t *testing.T) {
		fake := &fakeAuthenticator{}
		router := httpapi.NewRouter(&httpapi.Handlers{Authenticator: fake, Secret: &fakeSecret{}})
		want := []byte{1, 2, 3}

		do(t, router, http.MethodGet, "/v1/secrets/db/password", "")

		if !bytes.Equal(fake.token, want) {
			t.Errorf("got %x, want %x", fake.token, want)
		}
	})

	t.Run("the token is cleared after authentication", func(t *testing.T) {
		fake := &fakeAuthenticator{}
		router := httpapi.NewRouter(&httpapi.Handlers{Authenticator: fake, Secret: &fakeSecret{}})
		want := make([]byte, 3)

		do(t, router, http.MethodGet, "/v1/secrets/db/password", "")

		if !bytes.Equal(fake.given, want) {
			t.Errorf("got %x, want %x", fake.given, want)
		}
	})

	t.Run("a rejected request never reaches the handler", func(t *testing.T) {
		tests := []struct {
			name          string
			authorization string
			err           error
		}{
			{"no header", "", nil},
			{"rejected token", bearer, identity.ErrInvalidToken},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeSecret{}
				router := httpapi.NewRouter(&httpapi.Handlers{
					Authenticator: &fakeAuthenticator{err: tt.err},
					Secret:        fake,
				})

				doWithAuthorization(t, router, tt.authorization, http.MethodGet, "/v1/secrets/db/password", "")

				if fake.path != "" {
					t.Errorf("got path %q, want none", fake.path)
				}
			})
		}
	})

	t.Run("an authenticator error maps to its status", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"sealed", identity.ErrSealed, http.StatusServiceUnavailable, "the system is sealed"},
			{"unknown error", errors.New("disk on fire"), http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{
					Authenticator: &fakeAuthenticator{err: tt.err},
					Secret:        &fakeSecret{},
				})

				rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})

	t.Run("an unauthorized response challenges for a bearer token", func(t *testing.T) {
		tests := []struct {
			name          string
			authorization string
			err           error
		}{
			{"no header", "", nil},
			{"rejected token", bearer, identity.ErrInvalidToken},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{
					Authenticator: &fakeAuthenticator{err: tt.err},
					Secret:        &fakeSecret{},
				})

				rec := doWithAuthorization(t, router, tt.authorization, http.MethodGet, "/v1/secrets/db/password", "")

				if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("got %q, want %q", got, "Bearer")
				}
			})
		}
	})

	t.Run("seal without a token is unauthorized", func(t *testing.T) {
		fake := &fakeSystem{}
		router := httpapi.NewRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, System: fake})

		rec := doWithAuthorization(t, router, "", http.MethodPost, "/v1/sys/seal", "")

		assertError(t, rec, http.StatusUnauthorized, "missing or invalid token")
		if fake.sealed {
			t.Errorf("sealed: got true, want false")
		}
	})

	t.Run("the scheme is matched in any case", func(t *testing.T) {
		fake := &fakeAuthenticator{}
		router := httpapi.NewRouter(&httpapi.Handlers{Authenticator: fake, Secret: &fakeSecret{}})
		want := []byte{1, 2, 3}

		doWithAuthorization(t, router, "bearer AQID", http.MethodGet, "/v1/secrets/db/password", "")

		if !bytes.Equal(fake.token, want) {
			t.Errorf("got %x, want %x", fake.token, want)
		}
	})
}

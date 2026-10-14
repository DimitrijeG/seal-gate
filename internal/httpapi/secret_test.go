package httpapi_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

func TestSecret(t *testing.T) {
	t.Run("a written secret reaches the service decoded", func(t *testing.T) {
		fake := &fakeSecret{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

		rec := do(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI="}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !bytes.Equal(fake.putValue, []byte{1, 2}) {
			t.Errorf("got %x, want %x", fake.putValue, []byte{1, 2})
		}
	})

	t.Run("a ttl on put reaches the service as a duration", func(t *testing.T) {
		fake := &fakeSecret{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

		rec := do(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI=","ttl":3600}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if fake.putTTL != time.Hour {
			t.Errorf("got %v, want %v", fake.putTTL, time.Hour)
		}
	})

	t.Run("a read returns the value as base64", func(t *testing.T) {
		fake := &fakeSecret{getValue: []byte{1, 2}}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := "AQI="

		rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[secretBody](t, rec)

		if got.Value != want {
			t.Errorf("got %q, want %q", got.Value, want)
		}
	})

	t.Run("a read returns the expiry in UTC", func(t *testing.T) {
		expiresAt := time.Date(2026, 10, 1, 13, 0, 0, 0, time.FixedZone("UTC+2", 2*60*60))
		fake := &fakeSecret{getValue: []byte{1, 2}, getExpiresAt: expiresAt}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := "2026-10-01T11:00:00Z"

		rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[secretBody](t, rec)

		if got.ExpiresAt != want {
			t.Errorf("got %q, want %q", got.ExpiresAt, want)
		}
	})

	t.Run("a read without an expiry omits it", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{getValue: []byte{1, 2}}})

		rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[map[string]any](t, rec)

		if expiresAt, ok := got["expires_at"]; ok {
			t.Errorf("got %v, want no expires_at", expiresAt)
		}
	})

	t.Run("a read forbids caching", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{getValue: []byte{1, 2}}})
		want := "no-store"

		rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")

		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a generated secret is returned in base64 with 201", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{genValue: []byte{1, 2}}})
		want := "AQI="

		rec := do(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}
		got := decode[secretBody](t, rec)

		if got.Value != want {
			t.Errorf("got %q, want %q", got.Value, want)
		}
	})

	t.Run("a generate passes the path and length to the service", func(t *testing.T) {
		fake := &fakeSecret{genValue: make([]byte, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

		do(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32}`)

		if fake.path != "db/password" {
			t.Errorf("path: got %q, want %q", fake.path, "db/password")
		}
		if fake.genLength != 32 {
			t.Errorf("length: got %d, want 32", fake.genLength)
		}
	})

	t.Run("a ttl on generate reaches the service as a duration", func(t *testing.T) {
		fake := &fakeSecret{genValue: make([]byte, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

		rec := do(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32,"ttl":3600}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if fake.genTTL != time.Hour {
			t.Errorf("got %v, want %v", fake.genTTL, time.Hour)
		}
	})

	t.Run("a generated secret is cleared after the response is written", func(t *testing.T) {
		fake := &fakeSecret{genValue: bytes.Repeat([]byte{0xab}, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := make([]byte, 32)

		rec := do(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body)
		}

		if !bytes.Equal(fake.genValue, want) {
			t.Errorf("got %x, want %x", fake.genValue, want)
		}
	})

	t.Run("a generated secret forbids caching", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{genValue: make([]byte, 32)}})
		want := "no-store"

		rec := do(t, router, http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32}`)

		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a path under an action prefix is still a secret's path", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			path   string
			body   string
		}{
			{"put under generate", http.MethodPut, "generate/db/password", `{"value":"AQI="}`},
			{"get under generate", http.MethodGet, "generate/db/password", ""},
			{"delete under generate", http.MethodDelete, "generate/db/password", ""},
			{"put under rotate", http.MethodPut, "rotate/db/password", `{"value":"AQI="}`},
			{"get under rotate", http.MethodGet, "rotate/db/password", ""},
			{"delete under rotate", http.MethodDelete, "rotate/db/password", ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeSecret{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

				do(t, router, tt.method, "/v1/secrets/"+tt.path, tt.body)

				if fake.path != tt.path {
					t.Errorf("got %q, want %q", fake.path, tt.path)
				}
			})
		}
	})

	t.Run("a rotated secret is returned in base64 with 200", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{rotValue: []byte{1, 2}}})
		want := "AQI="

		rec := do(t, router, http.MethodPost, "/v1/secrets/rotate/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[secretBody](t, rec)

		if got.Value != want {
			t.Errorf("got %q, want %q", got.Value, want)
		}
	})

	t.Run("a rotate passes the path to the service", func(t *testing.T) {
		fake := &fakeSecret{rotValue: make([]byte, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := "db/password"

		do(t, router, http.MethodPost, "/v1/secrets/rotate/"+want, "")

		if fake.path != want {
			t.Errorf("got %q, want %q", fake.path, want)
		}
	})

	t.Run("a rotated secret is cleared after the response is written", func(t *testing.T) {
		fake := &fakeSecret{rotValue: bytes.Repeat([]byte{0xab}, 32)}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := make([]byte, 32)

		rec := do(t, router, http.MethodPost, "/v1/secrets/rotate/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if !bytes.Equal(fake.rotValue, want) {
			t.Errorf("got %x, want %x", fake.rotValue, want)
		}
	})

	t.Run("a rotated secret forbids caching", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{rotValue: make([]byte, 32)}})
		want := "no-store"

		rec := do(t, router, http.MethodPost, "/v1/secrets/rotate/db/password", "")

		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a delete returns no content", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{}})

		rec := do(t, router, http.MethodDelete, "/v1/secrets/db/password", "")

		if rec.Code != http.StatusNoContent {
			t.Errorf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("body: got %q, want empty", rec.Body)
		}
	})

	t.Run("each operation passes the full path to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			body   string
		}{
			{"put", http.MethodPut, `{"value":"AQI="}`},
			{"get", http.MethodGet, ""},
			{"delete", http.MethodDelete, ""},
		}

		want := "db/prod/password"
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeSecret{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

				do(t, router, tt.method, "/v1/secrets/"+want, tt.body)

				if fake.path != want {
					t.Errorf("got %q, want %q", fake.path, want)
				}
			})
		}
	})

	t.Run("each operation passes the authenticated principal to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			target string
			body   string
		}{
			{"get", http.MethodGet, "/v1/secrets/db/password", ""},
			{"put", http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI="}`},
			{"delete", http.MethodDelete, "/v1/secrets/db/password", ""},
			{"list", http.MethodGet, "/v1/secrets?prefix=db/", ""},
			{"generate", http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32}`},
			{"rotate", http.MethodPost, "/v1/secrets/rotate/db/password", ""},
		}

		want := authorization.NewEntityPrincipal(entityID, "dev")
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeSecret{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{principal: want}, Secret: fake})

				do(t, router, tt.method, tt.target, tt.body)

				if !reflect.DeepEqual(fake.principal, want) {
					t.Errorf("got %+v, want %+v", fake.principal, want)
				}
			})
		}
	})

	t.Run("a denied operation is forbidden", func(t *testing.T) {
		denied := fmt.Errorf("secret: %w", authorization.ErrDenied)
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{err: denied}})

		rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")

		assertError(t, rec, http.StatusForbidden, "permission denied")
	})

	t.Run("each operation reports the service's error", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			target string
			body   string
		}{
			{"put", http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI="}`},
			{"get", http.MethodGet, "/v1/secrets/db/password", ""},
			{"delete", http.MethodDelete, "/v1/secrets/db/password", ""},
			{"list", http.MethodGet, "/v1/secrets", ""},
			{"generate", http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32}`},
			{"rotate", http.MethodPost, "/v1/secrets/rotate/db/password", ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{err: secret.ErrSealed}})

				rec := do(t, router, tt.method, tt.target, tt.body)

				assertError(t, rec, http.StatusServiceUnavailable, "the system is sealed")
			})
		}
	})

	t.Run("an invalid TTL from the service is a bad request", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: &fakeSecret{err: secret.ErrInvalidTTL}})

		rec := do(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI=","ttl":-1}`)

		assertError(t, rec, http.StatusBadRequest, "invalid TTL")
	})

	t.Run("a ttl too large to hold is refused before the service", func(t *testing.T) {
		// One second past what a time.Duration can hold.
		tests := []struct {
			name   string
			method string
			target string
			body   string
		}{
			{"put", http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI=","ttl":9223372037}`},
			{"generate", http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32,"ttl":9223372037}`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeSecret{genValue: make([]byte, 32)}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

				rec := do(t, router, tt.method, tt.target, tt.body)

				assertError(t, rec, http.StatusBadRequest, "invalid TTL")
				if fake.path != "" {
					t.Errorf("path: got %q, want the service not called", fake.path)
				}
			})
		}
	})

	t.Run("the largest ttl that fits reaches the service", func(t *testing.T) {
		want := 9223372036 * time.Second
		tests := []struct {
			name   string
			method string
			target string
			body   string
			got    func(f *fakeSecret) time.Duration
		}{
			{"put", http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI=","ttl":9223372036}`,
				func(f *fakeSecret) time.Duration { return f.putTTL }},
			{"generate", http.MethodPost, "/v1/secrets/generate/db/password", `{"length":32,"ttl":9223372036}`,
				func(f *fakeSecret) time.Duration { return f.genTTL }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeSecret{genValue: make([]byte, 32)}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

				rec := do(t, router, tt.method, tt.target, tt.body)
				if rec.Code >= http.StatusBadRequest {
					t.Fatalf("status: got %d, want success: %s", rec.Code, rec.Body)
				}

				if got := tt.got(fake); got != want {
					t.Errorf("got %v, want %v", got, want)
				}
			})
		}
	})

	t.Run("a value of the maximum size is accepted", func(t *testing.T) {
		fake := &fakeSecret{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		value := base64.StdEncoding.EncodeToString(make([]byte, secret.MaxValueSize))

		rec := do(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"`+value+`"}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if len(fake.putValue) != secret.MaxValueSize {
			t.Errorf("got %d, want %d", len(fake.putValue), secret.MaxValueSize)
		}
	})

	t.Run("an absent value stores an empty secret", func(t *testing.T) {
		fake := &fakeSecret{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

		rec := do(t, router, http.MethodPut, "/v1/secrets/db/password", `{}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if len(fake.putValue) != 0 {
			t.Errorf("got %d, want 0", len(fake.putValue))
		}
	})

	t.Run("an empty secret reads as an empty string", func(t *testing.T) {
		fake := &fakeSecret{getValue: nil}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := `{"value":""}`

		rec := do(t, router, http.MethodGet, "/v1/secrets/db/password", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := strings.TrimSpace(rec.Body.String())

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a listing returns the service's paths", func(t *testing.T) {
		want := []string{"db/a", "db/b"}
		fake := &fakeSecret{listPaths: want}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

		rec := do(t, router, http.MethodGet, "/v1/secrets?prefix=db/", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[listBody](t, rec)

		if !slices.Equal(got.Paths, want) {
			t.Errorf("got %v, want %v", got.Paths, want)
		}
	})

	t.Run("a listing passes the prefix to the service", func(t *testing.T) {
		fake := &fakeSecret{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := "db/prod/"

		do(t, router, http.MethodGet, "/v1/secrets?prefix="+want, "")

		if fake.listPrefix != want {
			t.Errorf("got %q, want %q", fake.listPrefix, want)
		}
	})

	t.Run("a listing without a prefix lists everything", func(t *testing.T) {
		fake := &fakeSecret{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})

		rec := do(t, router, http.MethodGet, "/v1/secrets", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}

		if fake.listPrefix != "" {
			t.Errorf("got %q, want %q", fake.listPrefix, "")
		}
	})

	t.Run("an empty list is an empty array", func(t *testing.T) {
		fake := &fakeSecret{listPaths: nil}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Secret: fake})
		want := `{"paths":[]}`

		rec := do(t, router, http.MethodGet, "/v1/secrets", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := strings.TrimSpace(rec.Body.String())

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

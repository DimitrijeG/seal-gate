package httpapi_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

func TestSecret(t *testing.T) {
	t.Run("a written secret reaches the service decoded", func(t *testing.T) {
		fake := &fakeSecret{}
		router := httpapi.NewRouter(&httpapi.Handlers{Secret: fake})

		rec := do(t, router, http.MethodPut, "/v1/secrets/db/password", `{"value":"AQI="}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !bytes.Equal(fake.putValue, []byte{1, 2}) {
			t.Errorf("got %x, want %x", fake.putValue, []byte{1, 2})
		}
	})

	t.Run("a read returns the value as base64", func(t *testing.T) {
		fake := &fakeSecret{getValue: []byte{1, 2}}
		router := httpapi.NewRouter(&httpapi.Handlers{Secret: fake})
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

	t.Run("a delete returns no content", func(t *testing.T) {
		router := httpapi.NewRouter(&httpapi.Handlers{Secret: &fakeSecret{}})

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
				router := httpapi.NewRouter(&httpapi.Handlers{Secret: fake})

				do(t, router, tt.method, "/v1/secrets/"+want, tt.body)

				if fake.path != want {
					t.Errorf("got %q, want %q", fake.path, want)
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
			{"put", http.MethodPut, `{"value":"AQI="}`},
			{"get", http.MethodGet, ""},
			{"delete", http.MethodDelete, ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{Secret: &fakeSecret{err: secret.ErrSealed}})

				rec := do(t, router, tt.method, "/v1/secrets/db/password", tt.body)

				assertError(t, rec, http.StatusServiceUnavailable, "the system is sealed")
			})
		}
	})

	t.Run("a value of the maximum size is accepted", func(t *testing.T) {
		fake := &fakeSecret{}
		router := httpapi.NewRouter(&httpapi.Handlers{Secret: fake})
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
		router := httpapi.NewRouter(&httpapi.Handlers{Secret: fake})

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
		router := httpapi.NewRouter(&httpapi.Handlers{Secret: fake})
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
}

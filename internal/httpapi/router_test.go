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
					rec := httptest.NewRecorder()
					router := httpapi.NewRouter(&httpapi.Handlers{
						System: &fakeSystem{},
						Secret: &fakeSecret{},
						Policy: &fakePolicy{},
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
		}

		for _, route := range routes {
			t.Run(route.name, func(t *testing.T) {
				body := `{}` + strings.Repeat(" ", route.limit)
				want := fmt.Sprintf("request body exceeds %d bytes", route.limit)
				router := httpapi.NewRouter(&httpapi.Handlers{
					System: &fakeSystem{},
					Secret: &fakeSecret{},
					Policy: &fakePolicy{},
				})

				rec := do(t, router, route.method, route.path, body)

				assertError(t, rec, http.StatusRequestEntityTooLarge, want)
			})
		}
	})

	t.Run("a secret path that is not in its clean form is refused", func(t *testing.T) {
		tests := []struct{ name, target string }{
			{"parent segment", "/v1/secrets/db/../password"},
			{"current segment", "/v1/secrets/db/./password"},
			{"empty segment", "/v1/secrets/db//password"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{Secret: &fakeSecret{}})

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
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := httpapi.NewRouter(&httpapi.Handlers{Policy: &fakePolicy{}})

				rec := do(t, router, http.MethodPut, tt.target, devPolicyJSON)

				assertError(t, rec, http.StatusBadRequest, "invalid policy name")
			})
		}
	})
}

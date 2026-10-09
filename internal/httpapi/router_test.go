package httpapi_test

import (
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
			{"oversized", contentTypeJSON, `{}` + strings.Repeat(" ", 1<<20), http.StatusRequestEntityTooLarge, "request body exceeds 16384 bytes"},
			{"unknown field", contentTypeJSON, `{"nope":1}`, http.StatusBadRequest, `unknown field in request body: "nope"`},
		}

		for _, route := range routes {
			for _, tt := range tests {
				t.Run(route.name+" "+tt.name, func(t *testing.T) {
					router := httpapi.NewRouter(&httpapi.Handlers{System: &fakeSystem{}})
					req := httptest.NewRequest(route.method, route.path, strings.NewReader(tt.body))
					req.Header.Set("Content-Type", tt.contentType)
					rec := httptest.NewRecorder()

					router.ServeHTTP(rec, req)

					assertError(t, rec, tt.status, tt.message)
				})
			}
		}
	})
}

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequire(t *testing.T) {
	// Every route pairs require with identify, so only a direct call reaches this case.
	t.Run("a request identify never saw does not run", func(t *testing.T) {
		ran := false
		handler := (&Handlers{}).require(func(http.ResponseWriter, *http.Request) { ran = true })

		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/secrets/x", nil))

		if ran {
			t.Errorf("got the handler run, want it refused")
		}
	})
}

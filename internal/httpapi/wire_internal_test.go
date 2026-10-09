package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

const contentTypeJSON = "application/json"

func respond(t *testing.T, err error) (status int, contentType, message string) {
	t.Helper()
	rec := httptest.NewRecorder()
	writeError(rec, nil, err)

	contentType = rec.Header().Get("Content-Type")
	var body errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(body.Errors) != 1 {
		t.Fatalf("errors: got %v, want one message", body.Errors)
	}
	return rec.Code, contentType, body.Errors[0]
}

func TestWriteError(t *testing.T) {
	t.Run("an error is written as a JSON body", func(t *testing.T) {
		_, contentType, message := respond(t, system.ErrAlreadyInitialized)
		want := "already initialized"

		if contentType != contentTypeJSON {
			t.Errorf("Content-Type: got %q, want %q", contentType, contentTypeJSON)
		}
		if message != want {
			t.Errorf("message: got %q, want %q", message, want)
		}
	})

	t.Run("domain errors map to their status and own message", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"invalid seal config", system.ErrInvalidSealConfig, http.StatusBadRequest, "invalid seal configuration"},
			{"already initialized", system.ErrAlreadyInitialized, http.StatusConflict, "already initialized"},
			{"not initialized", system.ErrNotInitialized, http.StatusConflict, "not initialized"},
			{"already unsealed", system.ErrAlreadyUnsealed, http.StatusConflict, "already unsealed"},
			{"invalid share", system.ErrInvalidShare, http.StatusBadRequest, "invalid unseal share"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status, _, message := respond(t, tt.err)

				if status != tt.status {
					t.Errorf("status: got %d, want %d", status, tt.status)
				}
				if message != tt.message {
					t.Errorf("message: got %q, want %q", message, tt.message)
				}
			})
		}
	})

	t.Run("an unwritten handler is a 501", func(t *testing.T) {
		status, _, _ := respond(t, errNotImplemented)

		if status != http.StatusNotImplemented {
			t.Errorf("got %d, want %d", status, http.StatusNotImplemented)
		}
	})

	t.Run("a wrapped sentinel maps like the sentinel", func(t *testing.T) {
		err := fmt.Errorf("unseal: %w", system.ErrInvalidShare)
		want := http.StatusBadRequest

		status, _, _ := respond(t, err)

		if status != want {
			t.Errorf("got %d, want %d", status, want)
		}
	})

	t.Run("an unrecognised error is a generic 500 that hides its text", func(t *testing.T) {
		err := errors.New("bolt: /var/lib/seal-gate/data.db: permission denied")
		want := http.StatusInternalServerError

		status, _, message := respond(t, err)

		if status != want {
			t.Errorf("status: got %d, want %d", status, want)
		}
		if message != "internal error" {
			t.Errorf("message: got %q, want %q", message, "internal error")
		}
	})

	t.Run("an unrecognised error is logged for the operator", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		err := errors.New("bolt: /var/lib/seal-gate/data.db: permission denied")

		writeError(httptest.NewRecorder(), logger, err)

		if !strings.Contains(buf.String(), "data.db") {
			t.Errorf("got %q, want it to contain %q", buf.String(), "data.db")
		}
	})

	t.Run("a client error is not logged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		err := system.ErrNotInitialized

		writeError(httptest.NewRecorder(), logger, err)

		if buf.Len() != 0 {
			t.Errorf("got %q, want empty", buf.String())
		}
	})
}

// decodeTarget stands in for a handler's request type.
type decodeTarget struct {
	Shares int `json:"shares"`
}

func request(t *testing.T, contentType, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

// refuse decodes body and returns what the client would see for the error.
func refuse(t *testing.T, contentType, body string) (status int, message string) {
	t.Helper()
	err := decodeJSON(httptest.NewRecorder(), request(t, contentType, body), &decodeTarget{})
	status, _, message = respond(t, err)
	return status, message
}

// padded returns a valid decodeTarget body exactly n bytes long, padded with
// whitespace inside the object so it decodes only if read to the end.
func padded(n int) string {
	const head, tail = `{"shares":`, `5}`
	return head + strings.Repeat(" ", n-len(head)-len(tail)) + tail
}

func TestDecodeJSON(t *testing.T) {
	t.Run("a JSON object decodes into the target", func(t *testing.T) {
		var got decodeTarget
		r := request(t, contentTypeJSON, `{"shares": 5}`)

		err := decodeJSON(httptest.NewRecorder(), r, &got)
		if err != nil {
			t.Fatalf("decodeJSON: %v", err)
		}

		if got.Shares != 5 {
			t.Errorf("got %d, want %d", got.Shares, 5)
		}
	})

	t.Run("a JSON media type is accepted", func(t *testing.T) {
		tests := []struct {
			name        string
			contentType string
		}{
			{"plain", contentTypeJSON},
			{"with charset", contentTypeJSON + "; charset=utf-8"},
			{"mixed case", "Application/JSON"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				r := request(t, tt.contentType, `{}`)

				err := decodeJSON(httptest.NewRecorder(), r, &decodeTarget{})
				if err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a body that is not declared JSON is refused", func(t *testing.T) {
		tests := []struct {
			name        string
			contentType string
		}{
			{"no header", ""},
			{"not JSON", "text/plain"},
			{"malformed", ";;"},
		}

		want := "expected Content-Type application/json"
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status, message := refuse(t, tt.contentType, `{}`)

				if status != http.StatusUnsupportedMediaType {
					t.Errorf("status: got %d, want %d", status, http.StatusUnsupportedMediaType)
				}
				if message != want {
					t.Errorf("message: got %q, want %q", message, want)
				}
			})
		}
	})

	t.Run("a body that cannot be decoded is a 400 saying why", func(t *testing.T) {
		tests := []struct {
			name    string
			body    string
			message string
		}{
			{"empty body", ``, "request body is empty"},
			{"cut off", `{"shares":`, "request body ended mid-value"},
			{"malformed", `{"shares" 5}`, "malformed JSON at byte offset 11"},
			{"field of the wrong type", `{"shares": "five"}`, `field "shares" must be of type int`},
			// The decoder's own message would name our Go type.
			{"not an object", `["shares"]`, "request body must be a JSON object"},
			{"unknown field", `{"treshold": 3}`, `unknown field in request body: "treshold"`},
			{"trailing data", `{}{}`, "request body must contain a single JSON object"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status, message := refuse(t, contentTypeJSON, tt.body)

				if status != http.StatusBadRequest {
					t.Errorf("status: got %d, want %d", status, http.StatusBadRequest)
				}
				if message != tt.message {
					t.Errorf("message: got %q, want %q", message, tt.message)
				}
			})
		}
	})

	t.Run("a body at the size limit is accepted", func(t *testing.T) {
		r := request(t, contentTypeJSON, padded(maxBodyBytes))

		if err := decodeJSON(httptest.NewRecorder(), r, &decodeTarget{}); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a body past the size limit is a 413", func(t *testing.T) {
		tests := []struct {
			name string
			body string
		}{
			{"one byte over", padded(maxBodyBytes + 1)},
			// The object fits; only the read for trailing data crosses the limit.
			{"whitespace after the object", `{}` + strings.Repeat(" ", maxBodyBytes)},
		}

		want := fmt.Sprintf("request body exceeds %d bytes", maxBodyBytes)
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status, message := refuse(t, contentTypeJSON, tt.body)

				if status != http.StatusRequestEntityTooLarge {
					t.Errorf("status: got %d, want %d", status, http.StatusRequestEntityTooLarge)
				}
				if message != want {
					t.Errorf("message: got %q, want %q", message, want)
				}
			})
		}
	})
}

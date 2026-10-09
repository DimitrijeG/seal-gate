package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

type errorResponse struct {
	Errors []string `json:"errors"`
}

// Their text is sent to clients as is, so it carries no package prefix.
var (
	errUnsupportedMediaType = errors.New("expected Content-Type application/json")
	errUnknownField         = errors.New("unknown field in request body")
	errTrailingData         = errors.New("request body must contain a single JSON object")
	errNotImplemented       = errors.New("not implemented")
)

const (
	mediaTypeJSON = "application/json"
	maxBodyBytes  = 16 << 10
)

// writeError keeps the status mapping here so domain modules never import net/http.
// Unrecognised errors get a generic 500, since their text can carry storage detail.
func writeError(w http.ResponseWriter, logger *slog.Logger, err error) {
	status, message := classify(err)

	if status == http.StatusInternalServerError && logger != nil {
		logger.Error("request failed", "error", err)
	}

	writeJSON(w, status, errorResponse{Errors: []string{message}})
}

func classify(err error) (int, string) {
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
		sizeErr   *http.MaxBytesError
		base64Err base64.CorruptInputError
	)

	switch {
	// Request decoding: the client's mistake, so a specific 400 beats a 500
	// that sends the operator to our logs.
	case errors.Is(err, errUnsupportedMediaType):
		return http.StatusUnsupportedMediaType, err.Error()
	case errors.Is(err, io.EOF):
		return http.StatusBadRequest, "request body is empty"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return http.StatusBadRequest, "request body ended mid-value"
	case errors.As(err, &syntaxErr):
		return http.StatusBadRequest, fmt.Sprintf("malformed JSON at byte offset %d", syntaxErr.Offset)
	case errors.As(err, &typeErr):
		if typeErr.Field == "" {
			// The top-level mismatch would name our Go type.
			return http.StatusBadRequest, "request body must be a JSON object"
		}
		return http.StatusBadRequest, fmt.Sprintf("field %q must be of type %s", typeErr.Field, typeErr.Type)
	case errors.Is(err, errUnknownField),
		errors.Is(err, errTrailingData):
		return http.StatusBadRequest, err.Error()
	case errors.As(err, &sizeErr):
		return http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", sizeErr.Limit)
	case errors.As(err, &base64Err):
		return http.StatusBadRequest, "request body has a value that is not valid base64"

	case errors.Is(err, errNotImplemented):
		return http.StatusNotImplemented, err.Error()
	}

	for _, d := range domainErrors {
		if errors.Is(err, d.err) {
			return d.status, d.message
		}
	}

	// Infrastructure (storage, crypto, anything unmapped): its text can leak detail.
	return http.StatusInternalServerError, "internal error"
}

// domainErrors gives each domain sentinel its client message, so its prefixed
// text is never sent. Scanned in order: an error wrapping two takes the first.
var domainErrors = []struct {
	err     error
	status  int
	message string
}{
	{system.ErrInvalidSealConfig, http.StatusBadRequest, "invalid seal configuration"},
	{system.ErrAlreadyInitialized, http.StatusConflict, "already initialized"},
	{system.ErrNotInitialized, http.StatusConflict, "not initialized"},
	{system.ErrAlreadyUnsealed, http.StatusConflict, "already unsealed"},
	{system.ErrInvalidShare, http.StatusBadRequest, "invalid unseal share"},
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", mediaTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// decodeJSON rejects unknown fields: a misspelled threshold silently ignored
// would only surface later, when the shares no longer unseal.
func decodeJSON(w http.ResponseWriter, r *http.Request, into any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != mediaTypeJSON {
		return errUnsupportedMediaType
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()

	// The decoder reports unknown fields only as message text.
	const unknownFieldPrefix = "json: unknown field "
	if err := decoder.Decode(into); err != nil {
		if field, ok := strings.CutPrefix(err.Error(), unknownFieldPrefix); ok {
			return fmt.Errorf("%w: %s", errUnknownField, field)
		}
		return err
	}

	// Decode stops after one value; reading on catches trailing data and
	// padding past the size limit.
	var sizeErr *http.MaxBytesError
	switch err := decoder.Decode(&struct{}{}); {
	case errors.Is(err, io.EOF):
		return nil
	case errors.As(err, &sizeErr):
		return err
	default:
		return errTrailingData
	}
}

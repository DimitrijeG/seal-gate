package httpapi

import (
	"crypto/rand"
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
)

// audit records r before next runs and its response after, under one request ID; a request it cannot record does not run.
func (h *Handlers) audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := audit.Event{
			Time:      h.Clock.Now(),
			RequestID: rand.Text(),
			Kind:      audit.KindRequest,
			Method:    r.Method,
			Route:     r.Pattern,
			Path:      r.URL.Path,
		}
		// Fail closed: an action with no record is what audit exists to prevent.
		if err := h.Auditor.Record(r.Context(), event); err != nil {
			writeError(w, h.Logger, err)
			return
		}

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		event.Time = h.Clock.Now()
		event.Kind = audit.KindResponse
		event.Status = recorder.status
		// Logged, not refused: the action has already happened.
		if err := h.Auditor.Record(r.Context(), event); err != nil && h.Logger != nil {
			h.Logger.Error("audit response failed", "error", err)
		}
	})
}

// statusRecorder keeps the status a handler writes; one that only calls Write sends 200.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

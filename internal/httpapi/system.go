package httpapi

import (
	"net/http"
)

func (h *Handlers) handleInit(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleSeal(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

func (h *Handlers) handleUnseal(w http.ResponseWriter, r *http.Request) {
	writeError(w, h.Logger, errNotImplemented)
}

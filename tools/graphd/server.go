package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

//go:embed ui.html
var uiHTML []byte

// Server holds the last good graph and pushes rebuilds to connected browsers.
type Server struct {
	dir string

	mu      sync.RWMutex
	graph   *Graph
	lastErr string

	subsMu sync.Mutex
	subs   map[chan []byte]struct{}
}

func NewServer(dir string) *Server {
	return &Server{dir: dir, subs: make(map[chan []byte]struct{})}
}

// Rebuild reloads the graph and broadcasts it.
//
// A failed load never clears the current graph. The browser keeps showing the
// last good state with a stale badge, because a graph that vanishes on every
// half-typed identifier is one you stop opening.
func (s *Server) Rebuild() {
	graph, err := Load(s.dir)

	s.mu.Lock()
	if err != nil {
		s.lastErr = err.Error()
	} else {
		s.graph = graph
		s.lastErr = ""
	}
	payload := s.payloadLocked()
	s.mu.Unlock()

	if err != nil {
		log.Printf("rebuild failed (keeping last good graph): %v", err)
	} else {
		log.Printf("rebuilt: %d packages, %d imports, %d violations",
			len(graph.Nodes), len(graph.Edges), len(graph.Violations))
	}

	s.broadcast(payload)
}

type envelope struct {
	Graph *Graph `json:"graph"`
	Error string `json:"error,omitempty"`
	Stale bool   `json:"stale"`
	At    string `json:"at"`
}

func (s *Server) payloadLocked() []byte {
	body, err := json.Marshal(envelope{
		Graph: s.graph,
		Error: s.lastErr,
		Stale: s.lastErr != "",
		At:    time.Now().Format("15:04:05"),
	})
	if err != nil {
		return []byte(`{"error":"marshal failed"}`)
	}
	return body
}

func (s *Server) broadcast(payload []byte) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()

	for ch := range s.subs {
		select {
		case ch <- payload:
		default:
			// A browser that cannot keep up gets the next rebuild instead.
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(uiHTML)
	})

	mux.HandleFunc("GET /api/graph", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		payload := s.payloadLocked()
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	})

	mux.HandleFunc("GET /api/events", s.handleEvents)

	return mux
}

// handleEvents is the live channel. Server-sent events rather than a
// WebSocket: the traffic is one-directional, and SSE reconnects on its own.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 4)

	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()

	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
	}()

	// Send current state immediately so a reconnecting page is never blank.
	s.mu.RLock()
	initial := s.payloadLocked()
	s.mu.RUnlock()

	writeEvent(w, flusher, initial)

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case payload := <-ch:
			writeEvent(w, flusher, payload)
		case <-keepalive.C:
			_, _ = w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, flusher http.Flusher, payload []byte) {
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(payload)
	_, _ = w.Write([]byte("\n\n"))
	flusher.Flush()
}

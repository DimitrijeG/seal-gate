// Package file appends audit events to a file, one JSON object per line.
package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
)

// line is the file's own format, so renaming an Event field cannot change what operators parse.
type line struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id"`
	Kind      string    `json:"kind"`
	Principal string    `json:"principal"`
	Method    string    `json:"method"`
	Route     string    `json:"route"`
	Path      string    `json:"path"`
	Status    int       `json:"status,omitempty"`
}

// Sink appends each event to one file as a JSON line; it is safe for concurrent use.
type Sink struct {
	file *os.File
}

var _ audit.Sink = (*Sink)(nil)

// New opens path for appending, creating it readable and writable by its owner only.
func New(path string) (*Sink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("file: %w", err)
	}
	return &Sink{file: f}, nil
}

// Write ignores ctx, as a file write cannot be cancelled; the recorder's timeout bounds it.
func (s *Sink) Write(ctx context.Context, event audit.Event) error {
	encoded, err := json.Marshal(line{
		Time:      event.Time.UTC(),
		RequestID: event.RequestID,
		Kind:      string(event.Kind),
		Principal: event.Principal,
		Method:    event.Method,
		Route:     event.Route,
		Path:      event.Path,
		Status:    event.Status,
	})
	if err != nil {
		return fmt.Errorf("file: %w", err)
	}
	// One Write per line, so concurrent events never interleave within a line.
	if _, err := s.file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("file: %w", err)
	}
	return nil
}

func (s *Sink) Close() error {
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("file: %w", err)
	}
	return nil
}

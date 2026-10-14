package app

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/config"
)

// newAuditApplication returns an Application whose closers run at cleanup, and a directory for its sinks.
func newAuditApplication(t *testing.T) (*Application, string) {
	t.Helper()
	// Made first: cleanups run in reverse, and an open file blocks its removal on Windows.
	dir := t.TempDir()
	a := &Application{}
	t.Cleanup(func() {
		if err := a.close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return a, dir
}

func auditConfig(sinks ...config.AuditSinkConfig) *config.Config {
	return &config.Config{Audit: config.AuditConfig{Sinks: sinks}}
}

// fileAudit is one required file sink in a fresh directory, for a Build that must succeed.
func fileAudit(t *testing.T) config.AuditConfig {
	t.Helper()
	return config.AuditConfig{Sinks: []config.AuditSinkConfig{
		{Type: "file", Path: filepath.Join(t.TempDir(), "audit.log"), Required: true, Timeout: time.Second},
	}}
}

func TestAuditDestinations(t *testing.T) {
	t.Run("an opened sink closes with the application", func(t *testing.T) {
		a, dir := newAuditApplication(t)
		path := filepath.Join(dir, "audit.log")

		if _, err := a.auditDestinations(auditConfig(config.AuditSinkConfig{Type: "file", Path: path, Required: true, Timeout: time.Second})); err != nil {
			t.Fatalf("auditDestinations: %v", err)
		}

		if got := len(a.closers); got != 1 {
			t.Errorf("got %d closers, want 1", got)
		}
	})

	t.Run("a destination writes to its sink's file", func(t *testing.T) {
		a, dir := newAuditApplication(t)
		path := filepath.Join(dir, "audit.log")

		destinations, err := a.auditDestinations(auditConfig(config.AuditSinkConfig{Type: "file", Path: path, Required: true, Timeout: time.Second}))
		if err != nil {
			t.Fatalf("auditDestinations: %v", err)
		}
		if len(destinations) != 1 {
			t.Fatalf("got %d destinations, want 1", len(destinations))
		}
		if err := destinations[0].Sink.Write(t.Context(), audit.Event{Kind: audit.KindRequest}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		written, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if len(written) == 0 {
			t.Errorf("got an empty file, want one event")
		}
	})

	t.Run("a destination carries its sink's settings", func(t *testing.T) {
		a, dir := newAuditApplication(t)
		required := filepath.Join(dir, "required.log")
		optional := filepath.Join(dir, "optional.log")
		want := []audit.Destination{
			{Name: required, Required: true, Timeout: time.Second},
			{Name: optional, Required: false, Timeout: 2 * time.Second},
		}

		destinations, err := a.auditDestinations(auditConfig(
			config.AuditSinkConfig{Type: "file", Path: required, Required: true, Timeout: time.Second},
			config.AuditSinkConfig{Type: "file", Path: optional, Required: false, Timeout: 2 * time.Second},
		))
		if err != nil {
			t.Fatalf("auditDestinations: %v", err)
		}

		// The sinks are files, checked by the test above; this one compares the settings.
		for i := range destinations {
			destinations[i].Sink = nil
		}
		if !slices.Equal(destinations, want) {
			t.Errorf("got %+v, want %+v", destinations, want)
		}
	})

	t.Run("an unknown sink type is refused", func(t *testing.T) {
		a, dir := newAuditApplication(t)

		_, err := a.auditDestinations(auditConfig(config.AuditSinkConfig{Type: "nope", Path: filepath.Join(dir, "audit.log"), Timeout: time.Second}))

		if !errors.Is(err, errUnsupportedSink) {
			t.Errorf("got %v, want %v", err, errUnsupportedSink)
		}
	})

	t.Run("a sink that cannot be opened fails", func(t *testing.T) {
		a, dir := newAuditApplication(t)

		_, err := a.auditDestinations(auditConfig(config.AuditSinkConfig{Type: "file", Path: filepath.Join(dir, "missing", "audit.log"), Timeout: time.Second}))

		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("got %v, want %v", err, fs.ErrNotExist)
		}
	})

	t.Run("a sink opened before a refused one is still closed", func(t *testing.T) {
		a, dir := newAuditApplication(t)

		_, err := a.auditDestinations(auditConfig(
			config.AuditSinkConfig{Type: "file", Path: filepath.Join(dir, "audit.log"), Timeout: time.Second},
			config.AuditSinkConfig{Type: "nope", Timeout: time.Second},
		))
		if !errors.Is(err, errUnsupportedSink) {
			t.Fatalf("auditDestinations: got %v, want %v", err, errUnsupportedSink)
		}

		if got := len(a.closers); got != 1 {
			t.Errorf("got %d closers, want 1", got)
		}
	})
}

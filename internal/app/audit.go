package app

import (
	"errors"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/audit/file"
	"github.com/dimitrijegasic/seal-gate/internal/config"
)

var errUnsupportedSink = errors.New("app: audit: unsupported sink")

// auditDestinations opens each configured sink, adding its Close to a.closers as it opens, so a later failure still closes it.
func (a *Application) auditDestinations(cfg *config.Config) ([]audit.Destination, error) {
	var destinations []audit.Destination
	for _, sink := range cfg.Audit.Sinks {
		if sink.Type != "file" {
			return nil, fmt.Errorf("%w %q", errUnsupportedSink, sink.Type)
		}
		s, err := file.New(sink.Path)
		if err != nil {
			return nil, fmt.Errorf("app: audit: %w", err)
		}
		a.closers = append(a.closers, s.Close)
		destinations = append(destinations, audit.Destination{
			Name:     sink.Path,
			Sink:     s,
			Required: sink.Required,
			Timeout:  sink.Timeout,
		})
	}
	return destinations, nil
}

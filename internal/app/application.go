// Package app is the composition root: it builds every component from config and is the only package that names concrete implementations.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

// Application is the built service; stopping it seals, then releases what Build opened.
type Application struct {
	server  *httpapi.Server
	system  *system.Service
	logger  *slog.Logger
	closers []func() error
}

func Build(ctx context.Context, cfg *config.Config) (_ *Application, err error) {
	app := &Application{}

	// Release whatever was opened before a later step failed.
	defer func() {
		if err != nil {
			err = errors.Join(err, app.close())
		}
	}()

	infra, err := buildInfrastructure(cfg)
	if err != nil {
		return nil, err
	}
	app.logger = infra.logger

	backend, err := buildStorage(ctx, cfg)
	if err != nil {
		return nil, err
	}
	app.closers = append(app.closers, backend.Close)

	repositories := buildRepositories(backend, infra)
	services := buildServices(infra, repositories)

	app.system = services.system
	app.server = buildHTTP(cfg, services, infra.logger)

	return app, nil
}

func (a *Application) Run(ctx context.Context) error {
	err := a.server.Run(ctx)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	if err != nil {
		err = fmt.Errorf("app: serve: %w", err)
	}
	return errors.Join(err, a.close())
}

// close seals first, so no key outlives the backend, then runs every
// closer in reverse order, even after one fails.
func (a *Application) close() error {
	// Build's cleanup closes an application whose services may not exist yet.
	// Run's context is already cancelled here; sealing must not depend on it.
	if a.system != nil {
		a.system.Seal(context.Background())
	}

	var errs []error
	for _, closer := range slices.Backward(a.closers) {
		if err := closer(); err != nil {
			errs = append(errs, fmt.Errorf("app: close: %w", err))
		}
	}
	a.closers = nil
	return errors.Join(errs...)
}

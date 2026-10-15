// Package app is the composition root: it builds every component from config and is the only package that names concrete implementations.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/authorization"
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

	destinations, err := app.auditDestinations(cfg)
	if err != nil {
		return nil, err
	}
	auditor, err := audit.New(infra.logger, destinations...)
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}

	repositories := buildRepositories(backend, infra)
	services, err := buildServices(infra, repositories, auditor, cfg.Lifecycle.Interval)
	if err != nil {
		return nil, err
	}

	app.system = services.system
	app.server = buildHTTP(cfg, services, infra, auditor)

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
	var errs []error
	// Build's cleanup closes an application whose services may not exist yet.
	if a.system != nil {
		// Root, on a fresh context: Run's is cancelled by now, and no decision may stop the seal.
		if err := a.system.Seal(context.Background(), authorization.NewRootPrincipal()); err != nil {
			errs = append(errs, fmt.Errorf("app: seal: %w", err))
		}
	}

	for _, closer := range slices.Backward(a.closers) {
		if err := closer(); err != nil {
			errs = append(errs, fmt.Errorf("app: close: %w", err))
		}
	}
	a.closers = nil
	return errors.Join(errs...)
}

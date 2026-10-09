// Package app is the composition root: it builds every component from config and is the only package that names concrete implementations.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
)

type Application struct {
	server  *httpapi.Server
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

// close runs every closer in reverse order, even after one fails.
func (a *Application) close() error {
	var errs []error
	for i := len(a.closers) - 1; i >= 0; i-- {
		if err := a.closers[i](); err != nil {
			errs = append(errs, fmt.Errorf("app: close: %w", err))
		}
	}
	a.closers = nil
	return errors.Join(errs...)
}

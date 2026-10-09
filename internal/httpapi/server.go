// Package httpapi translates HTTP to application calls and back; it holds no business logic.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/config"
)

type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	grace      time.Duration
}

func NewServer(cfg *config.Config, handler http.Handler, logger *slog.Logger) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.HTTP.Address,
			Handler:           handler,
			ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
			ReadTimeout:       cfg.HTTP.ReadTimeout,
			WriteTimeout:      cfg.HTTP.WriteTimeout,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
		logger: logger,
		grace:  cfg.HTTP.GracefulShutdown,
	}
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("listening", "address", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("httpapi: %w", err)
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	s.logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.grace)
	defer cancel()

	// Past the grace period, force connections closed so handlers see their
	// request context cancelled before the caller tears down dependencies.
	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("httpapi: %w", errors.Join(err, s.httpServer.Close()))
	}
	return nil
}

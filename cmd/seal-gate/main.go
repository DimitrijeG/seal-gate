// Command seal-gate runs the secrets-management server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/app"
	"github.com/dimitrijegasic/seal-gate/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	buildCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	application, err := app.Build(buildCtx, cfg)
	if err != nil {
		return err
	}

	return application.Run(ctx)
}

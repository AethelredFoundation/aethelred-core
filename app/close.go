package app

import (
	"context"
	"errors"
)

// Close is called by the server on shutdown. It performs an ordered
// graceful shutdown of app components before closing the BaseApp.
func (app *AethelredApp) Close() error {
	var errs []error

	if err := app.GracefulShutdown(context.Background()); err != nil {
		errs = append(errs, err)
	}

	if app.BaseApp != nil {
		if err := app.BaseApp.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

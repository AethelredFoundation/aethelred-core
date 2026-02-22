package app

import (
	"fmt"
	"runtime/debug"
)

func (app *AethelredApp) recoverABCI(handler string, errp *error) {
	if r := recover(); r != nil {
		app.Logger().Error("CRITICAL: Panic recovered in ABCI handler",
			"handler", handler,
			"panic", fmt.Sprintf("%v", r),
			"stack", string(debug.Stack()),
		)
		if errp != nil {
			*errp = fmt.Errorf("panic in %s: %v", handler, r)
		}
	}
}

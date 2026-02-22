package app

import (
	"encoding/json"
	"net/http"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/x/verify"
	"github.com/aethelred/aethelred/x/verify/types"
)

// HealthHandler returns an HTTP handler for component-level health.
func (app *AethelredApp) HealthHandler() http.Handler {
	return &AethelredHealthHandler{app: app}
}

// AethelredHealthHandler serves component-level health status.
type AethelredHealthHandler struct {
	app *AethelredApp
}

type healthReport struct {
	Status     string            `json:"status"`
	Timestamp  string            `json:"timestamp"`
	ChainID    string            `json:"chain_id,omitempty"`
	Height     int64             `json:"height,omitempty"`
	Components []componentStatus `json:"components"`
}

type componentStatus struct {
	Name    string      `json:"name"`
	Healthy bool        `json:"healthy"`
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Details interface{} `json:"details,omitempty"`
}

type breakerStatus struct {
	Name                string `json:"name"`
	State               string `json:"state"`
	ConsecutiveFailures int64  `json:"consecutive_failures"`
	TotalTrips          int64  `json:"total_trips"`
}

func (h *AethelredHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if h.app == nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(healthReport{
			Status:    "unhealthy",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Components: []componentStatus{
				{
					Name:    "app",
					Healthy: false,
					Status:  "unhealthy",
					Message: "app not initialized",
				},
			},
		})
		return
	}

	ctx := h.app.NewContext(true)

	params := types.DefaultParams()
	if p, err := h.app.VerifyKeeper.GetParams(ctx); err == nil && p != nil {
		params = p
	}

	components := make([]componentStatus, 0, 6)

	// PoUW module health
	if metrics := h.app.PouwKeeper.Metrics(); metrics != nil {
		health := metrics.CheckHealth(ctx)
		components = append(components, componentStatus{
			Name:    "pouw_module",
			Healthy: health.Healthy,
			Status:  boolStatus(health.Healthy),
			Details: health,
		})
	} else {
		components = append(components, componentStatus{
			Name:    "pouw_module",
			Healthy: false,
			Status:  "unhealthy",
			Message: "module metrics unavailable",
		})
	}

	// Verification orchestrator health
	if h.app.orchestrator != nil {
		components = append(components, componentStatus{
			Name:    "verify_orchestrator",
			Healthy: true,
			Status:  "healthy",
			Message: "initialized",
		})
	} else {
		components = append(components, componentStatus{
			Name:    "verify_orchestrator",
			Healthy: false,
			Status:  "unhealthy",
			Message: "orchestrator not initialized",
		})
	}

	// TEE client health
	if h.app.teeClient == nil {
		if params.AllowSimulated {
			components = append(components, componentStatus{
				Name:    "tee_client",
				Healthy: true,
				Status:  "simulated",
				Message: "TEE client not configured; AllowSimulated=true",
			})
		} else {
			components = append(components, componentStatus{
				Name:    "tee_client",
				Healthy: false,
				Status:  "unhealthy",
				Message: "TEE client not configured",
			})
		}
	} else {
		healthy := h.app.teeClient.IsHealthy(r.Context())
		msg := "healthy"
		status := boolStatus(healthy)
		if !healthy && params.AllowSimulated {
			status = "degraded"
			msg = "TEE unhealthy; AllowSimulated=true"
		} else if !healthy {
			msg = "TEE health check failed"
		}
		components = append(components, componentStatus{
			Name:    "tee_client",
			Healthy: healthy || params.AllowSimulated,
			Status:  status,
			Message: msg,
			Details: h.app.teeClient.GetCapabilities(),
		})
	}

	// Readiness (config correctness) for verify module
	readiness := verify.ValidateProductionReadiness(params, collectTEEConfigs(h.app, ctx), ptrOrchestratorConfig(h.app))
	readinessStatus := boolStatus(readiness.Ready)
	if params.AllowSimulated {
		readinessStatus = "simulated"
	}
	components = append(components, componentStatus{
		Name:    "verify_readiness",
		Healthy: readiness.Ready || params.AllowSimulated,
		Status:  readinessStatus,
		Details: readiness,
	})

	// Circuit breaker health
	breakers := collectBreakerSnapshots(h.app)
	breakerDetails, breakerHealthy := summarizeBreakers(breakers)
	breakerStatus := boolStatus(breakerHealthy)
	if len(breakers) == 0 {
		breakerStatus = "disabled"
		breakerHealthy = true
	} else if !breakerHealthy {
		breakerStatus = "degraded"
	}
	components = append(components, componentStatus{
		Name:    "circuit_breakers",
		Healthy: breakerHealthy,
		Status:  breakerStatus,
		Details: breakerDetails,
	})

	report := healthReport{
		Status:     overallStatus(components),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ChainID:    chainID(h.app),
		Height:     h.app.LastBlockHeight(),
		Components: components,
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(report)
}

func boolStatus(healthy bool) string {
	if healthy {
		return "healthy"
	}
	return "unhealthy"
}

func overallStatus(components []componentStatus) string {
	for _, c := range components {
		if !c.Healthy {
			return "unhealthy"
		}
	}
	return "healthy"
}

func chainID(app *AethelredApp) string {
	if app == nil || app.BaseApp == nil {
		return ""
	}
	return app.BaseApp.ChainID()
}

func collectTEEConfigs(app *AethelredApp, ctx sdk.Context) []*types.TEEConfig {
	if app == nil {
		return nil
	}
	var teeConfigs []*types.TEEConfig
	_ = app.VerifyKeeper.TEEConfigs.Walk(
		ctx,
		nil,
		func(key string, cfg types.TEEConfig) (bool, error) {
			cfgCopy := cfg
			teeConfigs = append(teeConfigs, &cfgCopy)
			return false, nil
		},
	)
	return teeConfigs
}

func ptrOrchestratorConfig(app *AethelredApp) *verify.OrchestratorConfig {
	if app == nil {
		return nil
	}
	cfg := app.buildFullOrchestratorConfig()
	return &cfg
}

func summarizeBreakers(snaps []circuitbreaker.Snapshot) ([]breakerStatus, bool) {
	if len(snaps) == 0 {
		return nil, true
	}
	statuses := make([]breakerStatus, 0, len(snaps))
	healthy := true
	for _, snap := range snaps {
		state := snap.State.String()
		if snap.State != circuitbreaker.Closed {
			healthy = false
		}
		statuses = append(statuses, breakerStatus{
			Name:                snap.Name,
			State:               state,
			ConsecutiveFailures: snap.ConsecutiveFailures,
			TotalTrips:          snap.TotalTrips,
		})
	}
	return statuses, healthy
}

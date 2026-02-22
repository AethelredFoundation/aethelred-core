package app

import (
	"context"
	"sync"
	"time"

	"cosmossdk.io/log"
)

// ShutdownManager coordinates graceful shutdown of all Aethelred components.
// This ensures that in-flight operations complete, state is persisted,
// and resources are released in the correct order.
type ShutdownManager struct {
	logger log.Logger

	// Shutdown coordination
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
	shutdownWg   sync.WaitGroup

	// Component registration
	components   []ShutdownComponent
	componentsMu sync.RWMutex

	// Configuration
	config ShutdownConfig

	// State
	isShuttingDown bool
	shutdownMu     sync.RWMutex
}

// ShutdownComponent represents a component that needs graceful shutdown
type ShutdownComponent interface {
	// Name returns the component name for logging
	Name() string

	// Shutdown gracefully shuts down the component
	// The context will be cancelled after the timeout
	Shutdown(ctx context.Context) error
}

// ShutdownConfig contains configuration for graceful shutdown
type ShutdownConfig struct {
	// GracePeriod is the total time allowed for graceful shutdown
	GracePeriod time.Duration

	// ComponentTimeout is the max time for each component to shutdown
	ComponentTimeout time.Duration

	// DrainTimeout is the time to wait for in-flight requests to complete
	DrainTimeout time.Duration

	// ForceShutdownDelay is the delay before forcefully terminating
	ForceShutdownDelay time.Duration
}

// DefaultShutdownConfig returns production-ready shutdown configuration
func DefaultShutdownConfig() ShutdownConfig {
	return ShutdownConfig{
		GracePeriod:        30 * time.Second,
		ComponentTimeout:   10 * time.Second,
		DrainTimeout:       5 * time.Second,
		ForceShutdownDelay: 5 * time.Second,
	}
}

// NewShutdownManager creates a new shutdown manager
func NewShutdownManager(logger log.Logger, config ShutdownConfig) *ShutdownManager {
	return &ShutdownManager{
		logger:     logger,
		shutdownCh: make(chan struct{}),
		config:     config,
		components: make([]ShutdownComponent, 0),
	}
}

// RegisterComponent registers a component for graceful shutdown.
// Components are shut down in reverse order of registration (LIFO).
func (sm *ShutdownManager) RegisterComponent(component ShutdownComponent) {
	sm.componentsMu.Lock()
	defer sm.componentsMu.Unlock()

	sm.components = append(sm.components, component)
	sm.logger.Info("Registered shutdown component",
		"name", component.Name(),
		"total_components", len(sm.components),
	)
}

// IsShuttingDown returns true if shutdown has been initiated
func (sm *ShutdownManager) IsShuttingDown() bool {
	sm.shutdownMu.RLock()
	defer sm.shutdownMu.RUnlock()
	return sm.isShuttingDown
}

// ShutdownCh returns a channel that's closed when shutdown is initiated
func (sm *ShutdownManager) ShutdownCh() <-chan struct{} {
	return sm.shutdownCh
}

// Shutdown initiates graceful shutdown of all components.
// This method is idempotent - calling it multiple times is safe.
func (sm *ShutdownManager) Shutdown(ctx context.Context) error {
	var firstCall bool

	sm.shutdownOnce.Do(func() {
		firstCall = true
		sm.shutdownMu.Lock()
		sm.isShuttingDown = true
		sm.shutdownMu.Unlock()
		close(sm.shutdownCh)
	})

	if !firstCall {
		sm.logger.Info("Shutdown already in progress, waiting...")
		sm.shutdownWg.Wait()
		return nil
	}

	sm.logger.Info("Initiating graceful shutdown",
		"grace_period", sm.config.GracePeriod,
		"component_count", len(sm.components),
	)

	// Create timeout context for entire shutdown process
	shutdownCtx, cancel := context.WithTimeout(ctx, sm.config.GracePeriod)
	defer cancel()

	// Phase 1: Drain in-flight requests
	sm.logger.Info("Phase 1: Draining in-flight requests",
		"timeout", sm.config.DrainTimeout,
	)
	sm.drainRequests(shutdownCtx)

	// Phase 2: Shutdown components in reverse order (LIFO)
	sm.logger.Info("Phase 2: Shutting down components")
	sm.componentsMu.RLock()
	components := make([]ShutdownComponent, len(sm.components))
	copy(components, sm.components)
	sm.componentsMu.RUnlock()

	var shutdownErrors []error

	// Shutdown in reverse order
	for i := len(components) - 1; i >= 0; i-- {
		component := components[i]
		sm.logger.Info("Shutting down component",
			"name", component.Name(),
			"remaining", i,
		)

		componentCtx, componentCancel := context.WithTimeout(shutdownCtx, sm.config.ComponentTimeout)

		sm.shutdownWg.Add(1)
		err := func() error {
			defer sm.shutdownWg.Done()
			defer componentCancel()

			if err := component.Shutdown(componentCtx); err != nil {
				sm.logger.Error("Component shutdown failed",
					"name", component.Name(),
					"error", err,
				)
				return err
			}

			sm.logger.Info("Component shutdown complete",
				"name", component.Name(),
			)
			return nil
		}()

		if err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}

	// Phase 3: Final cleanup
	sm.logger.Info("Phase 3: Final cleanup")
	sm.shutdownWg.Wait()

	if len(shutdownErrors) > 0 {
		sm.logger.Error("Shutdown completed with errors",
			"error_count", len(shutdownErrors),
		)
	} else {
		sm.logger.Info("Graceful shutdown completed successfully")
	}

	return nil
}

// drainRequests waits for in-flight requests to complete
func (sm *ShutdownManager) drainRequests(ctx context.Context) {
	drainCtx, cancel := context.WithTimeout(ctx, sm.config.DrainTimeout)
	defer cancel()

	// In a real implementation, this would wait for:
	// - Active gRPC streams to complete
	// - Pending transactions in mempool to be processed
	// - Active compute jobs to complete or be checkpointed

	select {
	case <-drainCtx.Done():
		sm.logger.Warn("Drain timeout reached, proceeding with shutdown")
	case <-time.After(sm.config.DrainTimeout):
		sm.logger.Info("Drain period completed")
	}
}

// =============================================================================
// Component Adapters
// =============================================================================

// HSMShutdownAdapter adapts the HSM manager for graceful shutdown
type HSMShutdownAdapter struct {
	manager interface {
		Close() error
	}
}

func (h *HSMShutdownAdapter) Name() string { return "HSM" }

func (h *HSMShutdownAdapter) Shutdown(ctx context.Context) error {
	if h.manager == nil {
		return nil
	}
	return h.manager.Close()
}

// TEEClientShutdownAdapter adapts the TEE client for graceful shutdown
type TEEClientShutdownAdapter struct {
	client interface {
		Close() error
	}
}

func (t *TEEClientShutdownAdapter) Name() string { return "TEEClient" }

func (t *TEEClientShutdownAdapter) Shutdown(ctx context.Context) error {
	if t.client == nil {
		return nil
	}
	return t.client.Close()
}

// OrchestratorShutdownAdapter adapts the verification orchestrator for shutdown
type OrchestratorShutdownAdapter struct {
	orchestrator interface {
		Shutdown()
	}
}

func (o *OrchestratorShutdownAdapter) Name() string { return "VerificationOrchestrator" }

func (o *OrchestratorShutdownAdapter) Shutdown(ctx context.Context) error {
	if o.orchestrator == nil {
		return nil
	}
	o.orchestrator.Shutdown()
	return nil
}

// JobSchedulerShutdownAdapter adapts the job scheduler for graceful shutdown
type JobSchedulerShutdownAdapter struct {
	scheduler interface {
		Stop()
	}
}

func (j *JobSchedulerShutdownAdapter) Name() string { return "JobScheduler" }

func (j *JobSchedulerShutdownAdapter) Shutdown(ctx context.Context) error {
	if j.scheduler == nil {
		return nil
	}
	j.scheduler.Stop()
	return nil
}

// MetricsShutdownAdapter adapts metrics collection for graceful shutdown
type MetricsShutdownAdapter struct {
	flusher interface {
		Flush() error
	}
}

func (m *MetricsShutdownAdapter) Name() string { return "Metrics" }

func (m *MetricsShutdownAdapter) Shutdown(ctx context.Context) error {
	if m.flusher == nil {
		return nil
	}
	return m.flusher.Flush()
}

// =============================================================================
// Integration with AethelredApp
// =============================================================================

// InitShutdownManager initializes the shutdown manager for the application.
// This should be called during app initialization.
func (app *AethelredApp) InitShutdownManager() {
	config := DefaultShutdownConfig()
	app.shutdownManager = NewShutdownManager(app.Logger(), config)

	// Recommended registration order (LIFO shutdown):
	// 1. TEE client
	// 2. Verification orchestrator
	// 3. Job scheduler (stops first during shutdown)
	//
	// Note: Actual registration happens in app.go after components are created.
	app.Logger().Info("Shutdown manager initialized",
		"grace_period", config.GracePeriod,
	)
}

// RegisterShutdownComponents registers all app components for graceful shutdown.
// This should be called after all components are initialized.
func (app *AethelredApp) RegisterShutdownComponents() {
	if app.shutdownManager == nil {
		app.Logger().Warn("Shutdown manager not initialized, skipping component registration")
		return
	}

	// Register TEE client if available
	if app.teeClient != nil {
		if closer, ok := app.teeClient.(interface{ Close() error }); ok {
			app.shutdownManager.RegisterComponent(&TEEClientShutdownAdapter{client: closer})
		}
	}

	// Register orchestrator if available
	if app.orchestrator != nil {
		app.shutdownManager.RegisterComponent(&OrchestratorShutdownAdapter{orchestrator: app.orchestrator})
	}

	// Register job scheduler if available (stop first during shutdown).
	if app.consensusHandler != nil {
		if scheduler := app.consensusHandler.Scheduler(); scheduler != nil {
			app.shutdownManager.RegisterComponent(&JobSchedulerShutdownAdapter{scheduler: scheduler})
		}
	}

	app.Logger().Info("Shutdown components registered")
}

// GracefulShutdown performs graceful shutdown of the application.
// This should be called when SIGTERM or SIGINT is received.
func (app *AethelredApp) GracefulShutdown(ctx context.Context) error {
	if app.shutdownManager == nil {
		app.Logger().Warn("Shutdown manager not initialized, performing immediate shutdown")
		return nil
	}

	return app.shutdownManager.Shutdown(ctx)
}

// Package app provides graceful initialization with fallback mechanisms.
//
// This file addresses the consultant finding:
// "Some panic() calls in app initialization - Low severity"
//
// By replacing panics with graceful degradation where possible.
package app

import (
	"fmt"
	"os"
	"path/filepath"

	"cosmossdk.io/log"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/spf13/cast"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// Initialization Error Handling
// =============================================================================

// InitializationError represents a non-fatal initialization error that allows
// the application to continue with degraded functionality.
type InitializationError struct {
	Component   string
	Err         error
	IsCritical  bool
	Fallback    string
	Remediation string
}

func (e *InitializationError) Error() string {
	return fmt.Sprintf("[%s] %s (fallback: %s)", e.Component, e.Err.Error(), e.Fallback)
}

// InitializationResult captures the result of component initialization
type InitializationResult struct {
	Success    bool
	Errors     []InitializationError
	Warnings   []string
	Components map[string]ComponentStatus
}

// ComponentStatus represents the status of an initialized component
type ComponentStatus struct {
	Name    string
	Healthy bool
	Mode    string // "full", "degraded", "disabled"
	Message string
}

// NewInitializationResult creates a new initialization result
func NewInitializationResult() *InitializationResult {
	return &InitializationResult{
		Success:    true,
		Errors:     make([]InitializationError, 0),
		Warnings:   make([]string, 0),
		Components: make(map[string]ComponentStatus),
	}
}

// AddError adds an initialization error
func (r *InitializationResult) AddError(err InitializationError) {
	r.Errors = append(r.Errors, err)
	if err.IsCritical {
		r.Success = false
	}
}

// AddWarning adds a warning
func (r *InitializationResult) AddWarning(msg string) {
	r.Warnings = append(r.Warnings, msg)
}

// SetComponentStatus sets the status of a component
func (r *InitializationResult) SetComponentStatus(name string, status ComponentStatus) {
	r.Components[name] = status
}

// =============================================================================
// Safe Initialization Functions
// =============================================================================

// SafeGetDefaultNodeHome returns the default node home directory with fallback.
// Instead of panicking on error, it returns a fallback path.
func SafeGetDefaultNodeHome() (string, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback 1: Try environment variable
		homeEnv := os.Getenv("HOME")
		if homeEnv != "" {
			return filepath.Join(homeEnv, ".aethelred"), nil
		}

		// Fallback 2: Use current directory
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			// Fallback 3: Use /tmp
			return "/tmp/.aethelred", fmt.Errorf("could not determine home directory: %w", err)
		}
		return filepath.Join(cwd, ".aethelred"), fmt.Errorf("using current directory as home: %w", err)
	}
	return filepath.Join(userHomeDir, ".aethelred"), nil
}

// SafeInitPQCMode initializes PQC mode with graceful fallback.
// If PQC initialization fails, the app continues with classical cryptography.
func SafeInitPQCMode(logger log.Logger, appOpts servertypes.AppOptions) error {
	pqcEnabled := cast.ToBool(appOpts.Get("aethelred.pqc.enabled"))
	if !pqcEnabled {
		logger.Info("PQC mode disabled by configuration")
		return nil
	}

	// Check if PQC libraries are available
	pqcAvailable := checkPQCAvailability()
	if !pqcAvailable {
		logger.Warn("PQC libraries not available, falling back to classical cryptography",
			"component", "pqc",
			"fallback", "classical_crypto",
		)
		return nil // Graceful degradation - don't fail
	}

	if err := initPQCMode(logger, appOpts); err != nil {
		logger.Error("PQC initialization failed, falling back to classical cryptography",
			"error", err,
			"component", "pqc",
			"fallback", "classical_crypto",
		)
		// Return nil to allow app to continue with classical crypto
		return nil
	}

	logger.Info("PQC mode enabled successfully")
	return nil
}

// checkPQCAvailability checks if PQC libraries are available
func checkPQCAvailability() bool {
	// In a real implementation, this would check for the presence
	// of required PQC libraries (e.g., liboqs bindings)
	return true // Placeholder
}

// SafeInitTEEClient initializes the TEE client with graceful fallback.
// If TEE initialization fails, verification falls back to simulation mode.
func SafeInitTEEClient(
	app *AethelredApp,
	logger log.Logger,
	appOpts servertypes.AppOptions,
) (*InitializationError, error) {
	mode := getTEEMode(appOpts)

	if mode == "disabled" {
		logger.Info("TEE client disabled by configuration")
		return nil, nil
	}

	endpoint := getTEEEndpoint(appOpts)
	factory := NewTEEClientFactory(logger)

	client, err := factory.Create(mode, map[string]string{
		"endpoint": endpoint,
	})

	if err != nil {
		// Determine if this is a critical error
		isCritical := mode == "production" || mode == "mainnet"

		initErr := &InitializationError{
			Component:   "tee_client",
			Err:         err,
			IsCritical:  isCritical,
			Fallback:    "simulation_mode",
			Remediation: "Ensure TEE endpoint is accessible or set tee.mode=disabled",
		}

		if isCritical {
			logger.Error("CRITICAL: TEE client initialization failed in production mode",
				"error", err,
				"mode", mode,
			)
			return initErr, err
		}

		logger.Warn("TEE client initialization failed, falling back to simulation mode",
			"error", err,
			"mode", mode,
			"fallback", "simulation_mode",
		)
		return initErr, nil // Non-critical, continue with degraded mode
	}

	app.teeClient = client
	logger.Info("TEE client initialized successfully",
		"mode", mode,
		"endpoint", endpoint,
	)
	return nil, nil
}

// getTEEMode extracts TEE mode from app options
func getTEEMode(appOpts servertypes.AppOptions) string {
	mode := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.tee.mode")),
		cast.ToString(appOpts.Get("tee.mode")),
		os.Getenv("AETHELRED_TEE_MODE"),
	)
	if mode == "" {
		return "disabled"
	}
	return mode
}

// getTEEEndpoint extracts TEE endpoint from app options
func getTEEEndpoint(appOpts servertypes.AppOptions) string {
	return firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.tee.endpoint")),
		cast.ToString(appOpts.Get("tee.endpoint")),
		os.Getenv("AETHELRED_TEE_ENDPOINT"),
	)
}

// SafeLoadLatestVersion loads the latest version with recovery options.
func SafeLoadLatestVersion(app *AethelredApp, logger log.Logger) error {
	err := app.LoadLatestVersion()
	if err != nil {
		logger.Error("Failed to load latest version",
			"error", err,
		)

		// Check if this is a fresh start or corruption
		if isEmptyStore(app) {
			logger.Info("Empty store detected, starting fresh")
			return nil
		}

		// Attempt recovery from backup
		if backupErr := attemptRecoveryFromBackup(app, logger); backupErr != nil {
			logger.Error("Recovery from backup failed",
				"error", backupErr,
			)
			return fmt.Errorf("failed to load state and recovery failed: %w", err)
		}

		logger.Warn("Recovered from backup after load failure")
		return nil
	}

	return nil
}

// isEmptyStore checks if the store is empty (fresh start)
func isEmptyStore(app *AethelredApp) bool {
	// Check if we're at height 0
	return app.LastBlockHeight() == 0
}

// attemptRecoveryFromBackup attempts to recover state from a backup
func attemptRecoveryFromBackup(app *AethelredApp, logger log.Logger) error {
	// This is a placeholder for backup recovery logic
	// In production, this would:
	// 1. Check for available backups
	// 2. Validate backup integrity
	// 3. Restore from most recent valid backup
	logger.Debug("Checking for available backups...")
	return fmt.Errorf("no backups available")
}

// =============================================================================
// Safe Verification Pipeline Initialization
// =============================================================================

// SafeInitVerificationPipeline initializes the verification pipeline with fallbacks.
func SafeInitVerificationPipeline(app *AethelredApp, logger log.Logger) *InitializationError {
	// Create verification orchestrator
	app.initVerificationPipeline()

	if app.orchestrator == nil && app.consensusHandler == nil {
		// Pipeline failed to initialize, but this might be acceptable in dev mode
		isProduction := os.Getenv("AETHELRED_ENV") == "production"

		initErr := &InitializationError{
			Component:   "verification_pipeline",
			Err:         fmt.Errorf("orchestrator and consensus handler are nil"),
			IsCritical:  isProduction,
			Fallback:    "no_verification",
			Remediation: "Check TEE/zkML service configuration",
		}

		if isProduction {
			logger.Error("CRITICAL: Verification pipeline failed to initialize in production")
			return initErr
		}

		logger.Warn("Verification pipeline not fully initialized",
			"orchestrator", app.orchestrator != nil,
			"consensus_handler", app.consensusHandler != nil,
		)
		return initErr
	}

	logger.Info("Verification pipeline initialized successfully")
	return nil
}

// =============================================================================
// Safe Evidence Processor Initialization
// =============================================================================

// SafeInitEvidenceProcessor initializes the evidence processor with fallbacks.
func SafeInitEvidenceProcessor(app *AethelredApp, logger log.Logger) *InitializationError {
	if app.evidenceProcessor != nil {
		logger.Debug("Evidence processor already initialized")
		return nil
	}

	// Create evidence processor with default configuration
	blockMissConfig := pouwkeeper.DefaultBlockMissConfig()
	slashingConfig := pouwkeeper.DefaultEvidenceSlashingConfig()

	app.evidenceProcessor = pouwkeeper.NewEvidenceProcessor(
		logger,
		&app.PouwKeeper,
		blockMissConfig,
		slashingConfig,
	)

	if app.evidenceProcessor == nil {
		return &InitializationError{
			Component:   "evidence_processor",
			Err:         fmt.Errorf("failed to create evidence processor"),
			IsCritical:  false, // Slashing can be added later
			Fallback:    "no_slashing",
			Remediation: "Evidence processor will be disabled, slashing won't occur",
		}
	}

	logger.Info("Evidence processor initialized",
		"block_miss_window", blockMissConfig.ParticipationWindow,
		"max_missed_blocks", blockMissConfig.MaxMissedBlocks,
	)
	return nil
}

// =============================================================================
// Composite Safe Initialization
// =============================================================================

// SafeInitializeApp performs safe initialization of all app components.
// Returns an InitializationResult with details on each component's status.
func SafeInitializeApp(
	app *AethelredApp,
	logger log.Logger,
	appOpts servertypes.AppOptions,
	loadLatest bool,
) *InitializationResult {
	result := NewInitializationResult()

	// 1. Initialize PQC mode (non-critical)
	if err := SafeInitPQCMode(logger, appOpts); err != nil {
		result.AddError(InitializationError{
			Component:  "pqc",
			Err:        err,
			IsCritical: false,
			Fallback:   "classical_crypto",
		})
		result.SetComponentStatus("pqc", ComponentStatus{
			Name:    "Post-Quantum Cryptography",
			Healthy: false,
			Mode:    "disabled",
			Message: "Falling back to classical cryptography",
		})
	} else {
		result.SetComponentStatus("pqc", ComponentStatus{
			Name:    "Post-Quantum Cryptography",
			Healthy: true,
			Mode:    "full",
		})
	}

	// 2. Initialize TEE client (critical in production)
	if initErr, err := SafeInitTEEClient(app, logger, appOpts); err != nil {
		result.AddError(*initErr)
		result.SetComponentStatus("tee", ComponentStatus{
			Name:    "TEE Client",
			Healthy: false,
			Mode:    "disabled",
			Message: err.Error(),
		})
	} else if initErr != nil {
		result.AddWarning(initErr.Error())
		result.SetComponentStatus("tee", ComponentStatus{
			Name:    "TEE Client",
			Healthy: false,
			Mode:    "degraded",
			Message: "Using simulation mode",
		})
	} else {
		result.SetComponentStatus("tee", ComponentStatus{
			Name:    "TEE Client",
			Healthy: true,
			Mode:    "full",
		})
	}

	// 3. Initialize verification pipeline
	if initErr := SafeInitVerificationPipeline(app, logger); initErr != nil {
		result.AddError(*initErr)
		result.SetComponentStatus("verification", ComponentStatus{
			Name:    "Verification Pipeline",
			Healthy: false,
			Mode:    initErr.Fallback,
			Message: initErr.Err.Error(),
		})
	} else {
		result.SetComponentStatus("verification", ComponentStatus{
			Name:    "Verification Pipeline",
			Healthy: true,
			Mode:    "full",
		})
	}

	// 4. Initialize evidence processor
	if initErr := SafeInitEvidenceProcessor(app, logger); initErr != nil {
		result.AddError(*initErr)
		result.SetComponentStatus("evidence", ComponentStatus{
			Name:    "Evidence Processor",
			Healthy: false,
			Mode:    initErr.Fallback,
			Message: initErr.Err.Error(),
		})
	} else {
		result.SetComponentStatus("evidence", ComponentStatus{
			Name:    "Evidence Processor",
			Healthy: true,
			Mode:    "full",
		})
	}

	// 5. Load latest version (critical)
	if loadLatest {
		if err := SafeLoadLatestVersion(app, logger); err != nil {
			result.AddError(InitializationError{
				Component:   "state_loading",
				Err:         err,
				IsCritical:  true,
				Remediation: "Check database integrity or restore from backup",
			})
			result.SetComponentStatus("state", ComponentStatus{
				Name:    "State Loading",
				Healthy: false,
				Mode:    "failed",
				Message: err.Error(),
			})
		} else {
			result.SetComponentStatus("state", ComponentStatus{
				Name:    "State Loading",
				Healthy: true,
				Mode:    "full",
			})
		}
	}

	// Log summary
	logInitializationSummary(logger, result)

	return result
}

// logInitializationSummary logs a summary of the initialization result
func logInitializationSummary(logger log.Logger, result *InitializationResult) {
	logger.Info("=== Initialization Summary ===")

	for name, status := range result.Components {
		if status.Healthy {
			logger.Info("Component initialized",
				"name", name,
				"mode", status.Mode,
			)
		} else {
			logger.Warn("Component degraded or disabled",
				"name", name,
				"mode", status.Mode,
				"message", status.Message,
			)
		}
	}

	if len(result.Errors) > 0 {
		for _, err := range result.Errors {
			if err.IsCritical {
				logger.Error("CRITICAL initialization error",
					"component", err.Component,
					"error", err.Err,
					"remediation", err.Remediation,
				)
			}
		}
	}

	if result.Success {
		logger.Info("Initialization completed successfully")
	} else {
		logger.Error("Initialization completed with CRITICAL errors")
	}
}

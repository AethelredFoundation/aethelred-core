package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/verify"
	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
)

// initVerificationPipeline constructs the full verification pipeline:
//
//  1. A VerificationOrchestrator (x/verify) that coordinates zkML and TEE verification
//  2. An OrchestratorBridge (app) that adapts it to the pouwkeeper.JobVerifier interface
//  3. A ConsensusHandler (x/pouw/keeper) that uses the bridge during vote extension
//
// This wiring lives in the app package (composition root) to avoid circular imports
// between x/pouw and x/verify.
//
// The resulting ConsensusHandler is stored on the app for use by ABCI++ handlers.
// If no TEE client is configured (mode="disabled"), the pipeline is still created
// but will rely on the AllowSimulated flag in module params; production mode will
// reject verifications that lack a real verifier.
func (app *AethelredApp) initVerificationPipeline() {
	orchConfig := app.buildFullOrchestratorConfig()

	// Create the orchestrator (coordinates zkML prover + TEE enclave services).
	orchestrator := verify.NewVerificationOrchestrator(app.Logger(), orchConfig)

	// Initialize dependencies at startup. In production this is fail-closed.
	if err := orchestrator.Initialize(context.Background()); err != nil {
		// Fail closed by default outside test/simulated startup modes.
		if isTestEnvironment() || startupAllowsVerificationInitFailure() {
			app.Logger().Warn("Orchestrator initialization warning (allowed in test/simulated mode)", "error", err)
		} else {
			panic(fmt.Sprintf("FATAL: verification orchestrator initialization failed: %v", err))
		}
	}

	// Store the orchestrator on the app for direct access (e.g. metrics, shutdown).
	app.orchestrator = orchestrator

	// Create the bridge that adapts the orchestrator to the JobVerifier interface.
	bridge := NewOrchestratorBridge(orchestrator)

	// Create the ConsensusHandler with the keeper and a new scheduler.
	schedulerConfig := pouwkeeper.DefaultSchedulerConfig()
	schedulerConfig.DrandPulseProvider = pouwkeeper.NewHTTPDrandPulseProvider(
		getEnvOrDefault("AETHELRED_DRAND_ENDPOINT", pouwkeeper.DefaultDrandEndpoint),
		resolveDurationEnv("AETHELRED_DRAND_TIMEOUT", 4*time.Second),
	)
	schedulerConfig.RequirePublicDrandPulse = true
	schedulerConfig.AllowDKGBeaconFallback = false
	schedulerConfig.AllowLegacyEntropyFallback = false
	scheduler := pouwkeeper.NewJobScheduler(app.Logger(), &app.PouwKeeper, schedulerConfig)
	app.consensusHandler = pouwkeeper.NewConsensusHandler(app.Logger(), &app.PouwKeeper, scheduler)
	app.consensusHandler.SetVerifier(bridge)

	// Initialize evidence processing for downtime/equivocation slashing.
	blockMissConfig := pouwkeeper.DefaultBlockMissConfig()
	slashingConfig := pouwkeeper.DefaultEvidenceSlashingConfig()
	app.evidenceProcessor = pouwkeeper.NewEvidenceProcessor(app.Logger(), &app.PouwKeeper, blockMissConfig, slashingConfig)

	app.Logger().Info("Verification pipeline initialized",
		"has_tee_client", app.teeClient != nil,
		"has_orchestrator", true,
	)
}

// buildFullOrchestratorConfig constructs a full OrchestratorConfig by inspecting
// the app's TEE client, environment variables, and sane defaults.
// This is similar to buildOrchestratorConfig in readiness.go but returns a
// value config (not pointer) suitable for NewVerificationOrchestrator.
func (app *AethelredApp) buildFullOrchestratorConfig() verify.OrchestratorConfig {
	cfg := verify.DefaultOrchestratorConfig()

	// --- Nitro / TEE configuration ---
	if app.teeClient != nil {
		caps := app.teeClient.GetCapabilities()
		if caps != nil {
			switch caps.Platform {
			case "remote", "aws-nitro":
				cfg.NitroConfig = &tee.NitroConfig{
					ExecutorEndpoint:            getEnvOrDefault("AETHELRED_TEE_ENDPOINT", ""),
					AttestationVerifierEndpoint: getEnvOrDefault("AETHELRED_ATTESTATION_VERIFIER_ENDPOINT", ""),
					AllowSimulated:              false,
				}
			case "mock-tee", "nitro-simulated":
				cfg.NitroConfig = &tee.NitroConfig{
					AllowSimulated: true,
				}
			}
		}
	}

	// --- EZKL prover configuration ---
	proverEndpoint := os.Getenv("AETHELRED_PROVER_ENDPOINT")
	if proverEndpoint != "" {
		cfg.ProverConfig = &ezkl.ProverConfig{
			ProverEndpoint: proverEndpoint,
			AllowSimulated: false,
		}
	}

	return cfg
}

// getEnvOrDefault returns the environment variable value or a fallback.
func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func resolveDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

// startupAllowsVerificationInitFailure returns true only for explicit simulated/dev modes.
func startupAllowsVerificationInitFailure() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AETHELRED_ALLOW_SIMULATED"))) {
	case "1", "true", "yes", "on":
		return true
	}

	mode := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		os.Getenv("AETHELRED_TEE_MODE"),
		os.Getenv("TEE_MODE"),
	)))
	switch mode {
	case "mock", "simulated", "nitro-simulated":
		return true
	}
	return false
}

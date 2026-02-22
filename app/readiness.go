package app

import (
	"fmt"
	"os"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/crypto/pqc"
	"github.com/aethelred/aethelred/x/verify"
	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	"github.com/aethelred/aethelred/x/verify/types"
)

// RunProductionReadinessChecks validates that the node is properly configured
// for its operating mode. It should be called after genesis initialization
// and keeper setup, but before the node begins processing blocks.
//
// In dev mode (AllowSimulated=true), all checks pass with informational messages.
// In production mode (AllowSimulated=false), missing endpoints or configurations
// result in a fatal startup failure to prevent the node from participating in
// consensus without real verification capabilities.
//
// The ctx parameter must be a committed SDK context (e.g. from InitChainer
// or BeginBlocker at height 1).
func (app *AethelredApp) RunProductionReadinessChecks(ctx sdk.Context) verify.ReadinessReport {
	// Fetch current params from the verify keeper.
	params := types.DefaultParams()
	if p, err := app.VerifyKeeper.GetParams(ctx); err == nil && p != nil {
		params = p
	}

	// Collect active TEE configs from the keeper.
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

	// Build orchestrator config from the currently configured external services.
	orchConfig := app.buildOrchestratorConfig()

	report := verify.ValidateProductionReadiness(params, teeConfigs, orchConfig)

	// Enforce PQC readiness in production mode.
	if params != nil && !params.AllowSimulated {
		check := pqc.CheckPQCReadiness()
		mode := pqc.GetPQCMode()
		prodMode := mode == pqc.PQCModeProduction || mode == pqc.PQCModeHybrid
		passed := prodMode && check.IsProductionReady()
		if !passed {
			report.Ready = false
		}
		message := fmt.Sprintf("mode=%s, circl_available=%t, errors=%v",
			mode.String(),
			pqc.IsCirclAvailable(),
			check.Errors,
		)
		report.Checks = append(report.Checks, verify.ReadinessCheck{
			Name:    "pqc_production_ready",
			Passed:  passed,
			Message: message,
		})
	} else {
		report.Checks = append(report.Checks, verify.ReadinessCheck{
			Name:    "pqc_production_ready",
			Passed:  true,
			Message: fmt.Sprintf("dev mode (%s) — PQC enforcement skipped", pqc.GetPQCMode().String()),
		})
	}

	// Log the full report
	app.Logger().Info(report.String())

	// If not ready and we're in production mode, panic to prevent an
	// insecure validator from participating in consensus.
	if !report.Ready && !params.AllowSimulated {
		msg := fmt.Sprintf(
			"FATAL: Aethelred node is NOT production-ready.\n%s\n"+
				"Set AllowSimulated=true in genesis for dev/testnet, "+
				"or configure all required endpoints for mainnet.",
			report.String(),
		)
		// In test environments, don't panic — return the report and let
		// the caller decide how to handle it.
		if isTestEnvironment() {
			app.Logger().Error(msg)
		} else {
			panic(msg)
		}
	}

	// Endpoint reachability check.
	// In production mode, unreachable dependencies are a startup blocker.
	if orchConfig != nil {
		unreachable := verify.ValidateEndpointReachability(orchConfig)
		if len(unreachable) > 0 {
			report.Ready = false
			report.Checks = append(report.Checks, verify.ReadinessCheck{
				Name:    "endpoint_reachability",
				Passed:  false,
				Message: fmt.Sprintf("unreachable verification dependencies: %v", unreachable),
			})

			if params != nil && !params.AllowSimulated {
				msg := fmt.Sprintf("FATAL: verification dependency reachability failed in production mode: %v", unreachable)
				if isTestEnvironment() {
					app.Logger().Error(msg)
				} else {
					panic(msg)
				}
			}

			for _, u := range unreachable {
				app.Logger().Warn("Endpoint unreachable at startup", "endpoint", u)
			}
		}
	}

	return report
}

// buildOrchestratorConfig constructs an OrchestratorConfig from the app's
// current TEE and prover settings. This is used for readiness checks.
func (app *AethelredApp) buildOrchestratorConfig() *verify.OrchestratorConfig {
	cfg := &verify.OrchestratorConfig{}
	teeEndpoint := strings.TrimSpace(firstNonEmpty(
		os.Getenv("AETHELRED_TEE_ENDPOINT"),
		os.Getenv("TEE_ENDPOINT"),
	))
	attestationEndpoint := strings.TrimSpace(firstNonEmpty(
		os.Getenv("AETHELRED_ATTESTATION_VERIFIER_ENDPOINT"),
		os.Getenv("AETHELRED_TEE_ATTESTATION_ENDPOINT"),
	))
	teeMode := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		os.Getenv("AETHELRED_TEE_MODE"),
		os.Getenv("TEE_MODE"),
	)))
	allowSimulatedTEE := teeMode == "mock" || teeMode == "simulated" || teeMode == "nitro-simulated"

	// If we have a TEE client configured, extract endpoint info
	if app.teeClient != nil {
		caps := app.teeClient.GetCapabilities()
		if caps != nil {
			switch caps.Platform {
			case "remote", "aws-nitro":
				cfg.NitroConfig = &tee.NitroConfig{
					ExecutorEndpoint:            teeEndpoint,
					AttestationVerifierEndpoint: attestationEndpoint,
					AllowSimulated:              false,
				}
			case "mock-tee", "nitro-simulated":
				cfg.NitroConfig = &tee.NitroConfig{
					AllowSimulated: true,
				}
			}
		}
	}

	// If no TEE client-derived config exists, use explicit endpoint/mode settings.
	if cfg.NitroConfig == nil && (teeEndpoint != "" || attestationEndpoint != "" || allowSimulatedTEE) {
		cfg.NitroConfig = &tee.NitroConfig{
			ExecutorEndpoint:            teeEndpoint,
			AttestationVerifierEndpoint: attestationEndpoint,
			AllowSimulated:              allowSimulatedTEE,
		}
	}

	// Prover config: check environment for prover endpoint.
	// In a production deployment, this would come from app options
	// or the validator's local configuration file.
	proverEndpoint := os.Getenv("AETHELRED_PROVER_ENDPOINT")
	if proverEndpoint != "" {
		cfg.ProverConfig = &ezkl.ProverConfig{
			ProverEndpoint: proverEndpoint,
			AllowSimulated: false,
		}
	}

	return cfg
}

// isTestEnvironment detects if we're running in a test context.
// This prevents panics in unit tests while keeping the safety
// check active in production.
func isTestEnvironment() bool {
	// go test sets -test.run, -test.v etc. in os.Args
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	return os.Getenv("AETHELRED_TEST_MODE") == "1"
}

package verify

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	"github.com/aethelred/aethelred/x/verify/types"
)

// ReadinessCheck describes a single readiness verification.
type ReadinessCheck struct {
	Name    string
	Passed  bool
	Message string
}

// ReadinessReport summarizes the production readiness state.
type ReadinessReport struct {
	Ready  bool
	Checks []ReadinessCheck
}

// String returns a human-readable report.
func (r ReadinessReport) String() string {
	var b strings.Builder
	status := "READY"
	if !r.Ready {
		status = "NOT READY"
	}
	fmt.Fprintf(&b, "Production Readiness: %s\n", status)
	for _, c := range r.Checks {
		mark := "PASS"
		if !c.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "  [%s] %s: %s\n", mark, c.Name, c.Message)
	}
	return b.String()
}

// ValidateProductionReadiness checks whether the verify module is correctly
// configured for production use (AllowSimulated=false) with all required
// external endpoints set. Call this at node startup after configuration is
// loaded.
//
// When AllowSimulated is true (devnet/localnet), all checks pass with
// informational messages.
func ValidateProductionReadiness(
	params *types.Params,
	teeConfigs []*types.TEEConfig,
	orchConfig *OrchestratorConfig,
) ReadinessReport {
	report := ReadinessReport{Ready: true}

	if params == nil {
		report.Ready = false
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "params",
			Passed:  false,
			Message: "module params not loaded",
		})
		return report
	}

	// Check 1: AllowSimulated flag
	if params.AllowSimulated {
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "allow_simulated",
			Passed:  true,
			Message: "AllowSimulated=true — simulated verification enabled (dev mode)",
		})
		// In dev mode, skip remaining production-only checks
		return report
	}

	report.Checks = append(report.Checks, ReadinessCheck{
		Name:    "allow_simulated",
		Passed:  true,
		Message: "AllowSimulated=false — production mode enforced",
	})

	// Check 2: ZK Verifier Endpoint
	if params.ZkVerifierEndpoint == "" {
		report.Ready = false
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "zk_verifier_endpoint",
			Passed:  false,
			Message: "ZkVerifierEndpoint is empty — set to real EZKL verifier URL",
		})
	} else {
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "zk_verifier_endpoint",
			Passed:  true,
			Message: fmt.Sprintf("configured: %s", params.ZkVerifierEndpoint),
		})
	}

	// Check 3: TEE Attestation Endpoints
	activeCount := 0
	endpointCount := 0
	for _, cfg := range teeConfigs {
		if cfg == nil || !cfg.IsActive {
			continue
		}
		activeCount++
		if cfg.AttestationEndpoint != "" {
			endpointCount++
		}
	}

	if activeCount == 0 {
		report.Ready = false
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "tee_platforms",
			Passed:  false,
			Message: "no active TEE platforms configured",
		})
	} else if endpointCount < activeCount {
		report.Ready = false
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "tee_attestation_endpoints",
			Passed:  false,
			Message: fmt.Sprintf("%d/%d active TEE platforms missing attestation endpoint", activeCount-endpointCount, activeCount),
		})
	} else {
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "tee_attestation_endpoints",
			Passed:  true,
			Message: fmt.Sprintf("%d active TEE platforms with endpoints", endpointCount),
		})
	}

	// Check 4: Trusted Measurements
	trustedCount := 0
	for _, cfg := range teeConfigs {
		if cfg != nil && cfg.IsActive && len(cfg.TrustedMeasurements) > 0 {
			trustedCount++
		}
	}
	if activeCount > 0 && trustedCount < activeCount {
		report.Ready = false
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "trusted_measurements",
			Passed:  false,
			Message: fmt.Sprintf("%d/%d active TEE platforms missing trusted measurements", activeCount-trustedCount, activeCount),
		})
	} else if trustedCount == activeCount && activeCount > 0 {
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "trusted_measurements",
			Passed:  true,
			Message: fmt.Sprintf("%d platforms with trusted measurements", trustedCount),
		})
	}

	// Check 5: Orchestrator configuration
	if orchConfig != nil {
		orchChecks := validateOrchestratorConfig(orchConfig)
		for _, c := range orchChecks {
			if !c.Passed {
				report.Ready = false
			}
			report.Checks = append(report.Checks, c)
		}
	}

	// Check 6: Supported proof systems
	if len(params.SupportedProofSystems) == 0 {
		report.Ready = false
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "proof_systems",
			Passed:  false,
			Message: "no proof systems configured",
		})
	} else {
		report.Checks = append(report.Checks, ReadinessCheck{
			Name:    "proof_systems",
			Passed:  true,
			Message: fmt.Sprintf("supported: %v", params.SupportedProofSystems),
		})
	}

	return report
}

// validateOrchestratorConfig checks the orchestrator's external service config.
func validateOrchestratorConfig(cfg *OrchestratorConfig) []ReadinessCheck {
	var checks []ReadinessCheck

	// Check EZKL prover endpoint
	if cfg.ProverConfig != nil {
		pc := cfg.ProverConfig
		if pc.ProverEndpoint == "" && !pc.AllowSimulated {
			checks = append(checks, ReadinessCheck{
				Name:    "ezkl_prover_endpoint",
				Passed:  false,
				Message: "ProverEndpoint empty and AllowSimulated=false",
			})
		} else if pc.ProverEndpoint != "" {
			checks = append(checks, ReadinessCheck{
				Name:    "ezkl_prover_endpoint",
				Passed:  true,
				Message: fmt.Sprintf("configured: %s", pc.ProverEndpoint),
			})
		}
	}

	// Check Nitro executor endpoint
	if cfg.NitroConfig != nil {
		nc := cfg.NitroConfig
		if nc.ExecutorEndpoint == "" && !nc.AllowSimulated {
			checks = append(checks, ReadinessCheck{
				Name:    "nitro_executor_endpoint",
				Passed:  false,
				Message: "ExecutorEndpoint empty and AllowSimulated=false",
			})
		} else if nc.ExecutorEndpoint != "" {
			checks = append(checks, ReadinessCheck{
				Name:    "nitro_executor_endpoint",
				Passed:  true,
				Message: fmt.Sprintf("configured: %s", nc.ExecutorEndpoint),
			})
		}

		if nc.AttestationVerifierEndpoint == "" && !nc.AllowSimulated {
			checks = append(checks, ReadinessCheck{
				Name:    "attestation_verifier_endpoint",
				Passed:  false,
				Message: "AttestationVerifierEndpoint empty and AllowSimulated=false",
			})
		} else if nc.AttestationVerifierEndpoint != "" {
			checks = append(checks, ReadinessCheck{
				Name:    "attestation_verifier_endpoint",
				Passed:  true,
				Message: fmt.Sprintf("configured: %s", nc.AttestationVerifierEndpoint),
			})
		}
	}

	return checks
}

// ValidateEndpointReachability performs a basic health check against configured
// verification service endpoints. This is a best-effort check at startup.
// Returns nil if all endpoints respond, or a list of unreachable endpoints.
func ValidateEndpointReachability(orchConfig *OrchestratorConfig) []string {
	var unreachable []string

	if orchConfig == nil {
		return unreachable
	}

	// Check EZKL prover
	if orchConfig.ProverConfig != nil && orchConfig.ProverConfig.ProverEndpoint != "" {
		if !isEndpointReachable(orchConfig.ProverConfig.ProverEndpoint) {
			unreachable = append(unreachable, "ezkl-prover: "+orchConfig.ProverConfig.ProverEndpoint)
		}
	}

	// Check Nitro executor
	if orchConfig.NitroConfig != nil {
		if orchConfig.NitroConfig.ExecutorEndpoint != "" {
			if !isEndpointReachable(orchConfig.NitroConfig.ExecutorEndpoint) {
				unreachable = append(unreachable, "nitro-executor: "+orchConfig.NitroConfig.ExecutorEndpoint)
			}
		}
		if orchConfig.NitroConfig.AttestationVerifierEndpoint != "" {
			if !isEndpointReachable(orchConfig.NitroConfig.AttestationVerifierEndpoint) {
				unreachable = append(unreachable, "attestation-verifier: "+orchConfig.NitroConfig.AttestationVerifierEndpoint)
			}
		}
	}

	return unreachable
}

// isEndpointReachable performs a bounded HTTP health check against the endpoint.
// It treats any HTTP response as reachable (including 4xx), while network/timeouts
// are considered unreachable.
func isEndpointReachable(endpoint string) bool {
	probes := endpointProbeURLs(endpoint)
	if len(probes) == 0 {
		return false
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for _, probe := range probes {
		req, err := http.NewRequest(http.MethodGet, probe, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return true
		}
	}
	return false
}

func endpointProbeURLs(endpoint string) []string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "http://" + endpoint
	}

	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return nil
	}

	normalized := strings.TrimRight(parsed.String(), "/")
	if normalized == "" {
		return nil
	}

	var probes []string
	if parsed.Path != "" && parsed.Path != "/" {
		probes = append(probes, normalized)
	}

	if !strings.HasSuffix(normalized, "/health") {
		root := *parsed
		root.Path = "/health"
		root.RawQuery = ""
		root.Fragment = ""
		probes = append(probes, root.String())
	}
	probes = append(probes, normalized)

	seen := make(map[string]struct{}, len(probes))
	unique := make([]string, 0, len(probes))
	for _, p := range probes {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}
	return unique
}

// ProverConfig re-exports for package visibility in readiness checks.
// Avoids the need to import ezkl directly when using ValidateProductionReadiness.
type ProverConfigRef = ezkl.ProverConfig
type NitroConfigRef = tee.NitroConfig

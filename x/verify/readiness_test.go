package verify

import (
	"strings"
	"testing"

	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	"github.com/aethelred/aethelred/x/verify/types"
)

func TestValidateProductionReadiness_AllowSimulated(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = true

	report := ValidateProductionReadiness(params, nil, nil)
	if !report.Ready {
		t.Fatalf("expected readiness to pass in simulated mode")
	}
	if len(report.Checks) == 0 {
		t.Fatalf("expected readiness checks")
	}
}

func TestReadinessReportString(t *testing.T) {
	report := ReadinessReport{
		Ready: false,
		Checks: []ReadinessCheck{
			{Name: "check-a", Passed: true, Message: "ok"},
			{Name: "check-b", Passed: false, Message: "bad"},
		},
	}
	out := report.String()
	if !strings.Contains(out, "NOT READY") {
		t.Fatalf("expected NOT READY in report output, got %s", out)
	}
	if !strings.Contains(out, "[PASS] check-a") || !strings.Contains(out, "[FAIL] check-b") {
		t.Fatalf("expected check lines in report output, got %s", out)
	}
}

func TestValidateProductionReadiness_ProductionFailures(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = ""
	params.SupportedProofSystems = nil

	report := ValidateProductionReadiness(params, nil, nil)
	if report.Ready {
		t.Fatalf("expected readiness to fail when missing config")
	}
}

func TestValidateProductionReadiness_NilParams(t *testing.T) {
	report := ValidateProductionReadiness(nil, nil, nil)
	if report.Ready {
		t.Fatalf("expected readiness failure for nil params")
	}
	if !containsAnyReadinessCheck(report.Checks, "params", false) {
		t.Fatalf("expected params failure check, got %+v", report.Checks)
	}
}

func TestValidateProductionReadiness_OrchestratorConfig(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{{
		Platform:            types.TEEPlatformAWSNitro,
		IsActive:            true,
		AttestationEndpoint: "https://attest",
		TrustedMeasurements: [][]byte{[]byte("trusted-measurement")},
	}}

	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "https://prover"},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "https://exec",
			AttestationVerifierEndpoint: "https://attest-verifier",
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, orch)
	if !report.Ready {
		t.Fatalf("expected readiness to pass with configured endpoints")
	}
}

func TestValidateProductionReadiness_TrustedMeasurementsRequiredInProduction(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{{
		Platform:            types.TEEPlatformAWSNitro,
		IsActive:            true,
		AttestationEndpoint: "https://attest",
		TrustedMeasurements: nil,
	}}

	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "https://prover"},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "https://exec",
			AttestationVerifierEndpoint: "https://attest-verifier",
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, orch)
	if report.Ready {
		t.Fatalf("expected readiness to fail when trusted measurements are missing")
	}
	if !containsAnyReadinessCheck(report.Checks, "trusted_measurements", false) {
		t.Fatalf("expected trusted_measurements check to fail, got %+v", report.Checks)
	}
}

func TestValidateProductionReadiness_PartialTrustedMeasurementsFail(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{
		{
			Platform:            types.TEEPlatformAWSNitro,
			IsActive:            true,
			AttestationEndpoint: "https://attest-1",
			TrustedMeasurements: [][]byte{[]byte("m1")},
		},
		{
			Platform:            types.TEEPlatformIntelSGX,
			IsActive:            true,
			AttestationEndpoint: "https://attest-2",
			TrustedMeasurements: nil,
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, nil)
	if report.Ready {
		t.Fatalf("expected readiness to fail when only a subset of active platforms has trusted measurements")
	}
	if !containsAnyReadinessCheck(report.Checks, "trusted_measurements", false) {
		t.Fatalf("expected trusted_measurements check to fail, got %+v", report.Checks)
	}
}

func TestValidateProductionReadiness_MissingAttestationEndpointFails(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{
		{
			Platform:            types.TEEPlatformAWSNitro,
			IsActive:            true,
			AttestationEndpoint: "",
			TrustedMeasurements: [][]byte{[]byte("m1")},
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, nil)
	if report.Ready {
		t.Fatalf("expected readiness failure when attestation endpoint is missing")
	}
	if !containsAnyReadinessCheck(report.Checks, "tee_attestation_endpoints", false) {
		t.Fatalf("expected tee_attestation_endpoints failure, got %+v", report.Checks)
	}
}

func TestValidateEndpointReachability_NoConfig(t *testing.T) {
	if unreachable := ValidateEndpointReachability(nil); len(unreachable) != 0 {
		t.Fatalf("expected no unreachable endpoints")
	}
}

func TestValidateEndpointReachability(t *testing.T) {
	unreachableEndpoint := "http://127.0.0.1:1"
	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{
			AllowSimulated: false,
			ProverEndpoint: unreachableEndpoint + "/prove",
		},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            unreachableEndpoint,
			AttestationVerifierEndpoint: "http://127.0.0.1:2",
		},
	}

	unreachable := ValidateEndpointReachability(orch)
	if len(unreachable) != 3 {
		t.Fatalf("expected exactly three unreachable endpoints, got %d (%v)", len(unreachable), unreachable)
	}
	if !containsAny(unreachable, "ezkl-prover") {
		t.Fatalf("expected ezkl-prover to be unreachable, got %v", unreachable)
	}
	if !containsAny(unreachable, "nitro-executor") {
		t.Fatalf("expected nitro-executor to be unreachable, got %v", unreachable)
	}
	if !containsAny(unreachable, "attestation-verifier") {
		t.Fatalf("expected attestation-verifier to be unreachable, got %v", unreachable)
	}
}

func containsAny(values []string, part string) bool {
	for _, v := range values {
		if strings.Contains(v, part) {
			return true
		}
	}
	return false
}

func TestEndpointProbeURLs(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		want     []string
	}{
		{
			name:     "host only",
			endpoint: "localhost:8546",
			want:     []string{"http://localhost:8546/health", "http://localhost:8546"},
		},
		{
			name:     "path endpoint",
			endpoint: "https://example.com/prove",
			want:     []string{"https://example.com/prove", "https://example.com/health"},
		},
		{
			name:     "health endpoint",
			endpoint: "https://example.com/health",
			want:     []string{"https://example.com/health"},
		},
		{
			name:     "empty endpoint",
			endpoint: " ",
			want:     nil,
		},
		{
			name:     "invalid parse",
			endpoint: "http://[::1",
			want:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := endpointProbeURLs(tc.endpoint)
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d probes, got %d (%v)", len(tc.want), len(got), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("probe[%d]: expected %q, got %q", i, tc.want[i], got[i])
				}
			}
		})
	}
}

func TestIsEndpointReachable_BlankEndpoint(t *testing.T) {
	if isEndpointReachable(" ") {
		t.Fatalf("blank endpoint must not be considered reachable")
	}
}

func TestValidateOrchestratorConfig_AllBranches(t *testing.T) {
	checks := validateOrchestratorConfig(&OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{
			AllowSimulated: false,
			ProverEndpoint: "",
		},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "",
			AttestationVerifierEndpoint: "",
		},
	})

	if !containsAnyReadinessCheck(checks, "ezkl_prover_endpoint", false) {
		t.Fatalf("expected prover endpoint failure, got %+v", checks)
	}
	if !containsAnyReadinessCheck(checks, "nitro_executor_endpoint", false) {
		t.Fatalf("expected nitro executor endpoint failure, got %+v", checks)
	}
	if !containsAnyReadinessCheck(checks, "attestation_verifier_endpoint", false) {
		t.Fatalf("expected attestation verifier endpoint failure, got %+v", checks)
	}
}

func TestValidateProductionReadiness_OrchestratorMissingEndpoint(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{{
		Platform:            types.TEEPlatformAWSNitro,
		IsActive:            true,
		AttestationEndpoint: "https://attest",
		TrustedMeasurements: [][]byte{[]byte("trusted-measurement")},
	}}

	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: ""},
		NitroConfig:  &tee.NitroConfig{AllowSimulated: true},
	}

	report := ValidateProductionReadiness(params, teeConfigs, orch)
	if report.Ready {
		t.Fatalf("expected readiness to fail when prover endpoint missing")
	}
}

func containsAnyReadinessCheck(checks []ReadinessCheck, name string, passed bool) bool {
	for _, c := range checks {
		if c.Name == name && c.Passed == passed {
			return true
		}
	}
	return false
}

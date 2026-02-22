package types_test

import (
	"testing"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// NEGATIVE-CASE TESTS: x/pouw/types genesis and parameter validation
// =============================================================================

func TestNegative_Genesis_NilParams(t *testing.T) {
	gs := types.GenesisState{
		Params: nil,
	}
	err := gs.Validate()
	assertErr(t, err, "params must be set")
}

func TestNegative_Genesis_ZeroMinValidators(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.Params.MinValidators = 0
	err := gs.Validate()
	assertErr(t, err, "min_validators must be positive")
}

func TestNegative_Genesis_NegativeMinValidators(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.Params.MinValidators = -1
	err := gs.Validate()
	assertErr(t, err, "min_validators must be positive")
}

func TestNegative_Genesis_ConsensusThresholdTooLow(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.Params.ConsensusThreshold = 49
	err := gs.Validate()
	assertErr(t, err, "consensus_threshold must be between 50 and 100")
}

func TestNegative_Genesis_ConsensusThresholdTooHigh(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.Params.ConsensusThreshold = 101
	err := gs.Validate()
	assertErr(t, err, "consensus_threshold must be between 50 and 100")
}

func TestNegative_Genesis_ZeroJobTimeout(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.Params.JobTimeoutBlocks = 0
	err := gs.Validate()
	assertErr(t, err, "job_timeout_blocks must be positive")
}

func TestNegative_Genesis_ZeroMaxJobs(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.Params.MaxJobsPerBlock = 0
	err := gs.Validate()
	assertErr(t, err, "max_jobs_per_block must be positive")
}

func TestNegative_Genesis_NilJob(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.Jobs = []*types.ComputeJob{nil}
	err := gs.Validate()
	assertErr(t, err, "job at index 0 is nil")
}

func TestNegative_Genesis_EmptyCapabilityAddress(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.ValidatorCapabilities = []*types.ValidatorCapability{
		{Address: ""},
	}
	err := gs.Validate()
	assertErr(t, err, "validator capability missing address")
}

func TestNegative_Genesis_NilCapability(t *testing.T) {
	gs := *types.DefaultGenesis()
	gs.ValidatorCapabilities = []*types.ValidatorCapability{nil}
	err := gs.Validate()
	assertErr(t, err, "validator capability missing address")
}

// ---------------------------------------------------------------------------
// Policy: Default params must have AllowSimulated=false
// ---------------------------------------------------------------------------

func TestPolicy_DefaultParamsAllowSimulatedFalse(t *testing.T) {
	params := types.DefaultParams()
	if params.AllowSimulated {
		t.Fatal("POLICY VIOLATION: DefaultParams has AllowSimulated=true — must be false")
	}

	if params.ConsensusThreshold != 67 {
		t.Errorf("expected default consensus threshold 67, got %d", params.ConsensusThreshold)
	}

	if params.MinValidators != 3 {
		t.Errorf("expected default min validators 3, got %d", params.MinValidators)
	}

	if !params.RequireTeeAttestation {
		t.Error("RequireTeeAttestation should be true by default")
	}

	t.Logf("Default params: AllowSimulated=%v, Threshold=%d, MinValidators=%d",
		params.AllowSimulated, params.ConsensusThreshold, params.MinValidators)
}

// ---------------------------------------------------------------------------
// Positive: valid default genesis passes
// ---------------------------------------------------------------------------

func TestPositive_DefaultGenesis_IsValid(t *testing.T) {
	gs := types.DefaultGenesis()
	err := gs.Validate()
	if err != nil {
		t.Fatalf("default genesis should be valid: %v", err)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func assertErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	found := false
	for i := 0; i <= len(err.Error())-len(substr); i++ {
		if err.Error()[i:i+len(substr)] == substr {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error containing %q, got: %s", substr, err.Error())
	}
	t.Logf("OK: correctly rejected: %s", err.Error())
}

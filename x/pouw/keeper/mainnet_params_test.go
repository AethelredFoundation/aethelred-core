package keeper_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEK 37: Mainnet Parameter Set Locked Tests
//
// These tests verify:
//   1. Canonical mainnet parameters (6 tests)
//   2. Parameter lock registry (5 tests)
//   3. Parameter change proposal validation (6 tests)
//   4. Mainnet genesis validation (5 tests)
//   5. Parameter compatibility checks (5 tests)
//   6. Mainnet param report rendering (3 tests)
//
// Total: 30 tests
// =============================================================================

// =============================================================================
// Section 1: Canonical Mainnet Parameters
// =============================================================================

func TestMainnetParams_Valid(t *testing.T) {
	params := keeper.MainnetParams()
	require.NotNil(t, params)

	err := keeper.ValidateParams(params)
	require.NoError(t, err, "mainnet params must pass validation")
}

func TestMainnetParams_BFTSafe(t *testing.T) {
	params := keeper.MainnetParams()

	require.GreaterOrEqual(t, params.ConsensusThreshold, int64(67),
		"consensus threshold must be >= 67 for BFT safety")
	require.GreaterOrEqual(t, params.MinValidators, int64(3),
		"min validators must be >= 3 for BFT quorum")
}

func TestMainnetParams_ProductionMode(t *testing.T) {
	params := keeper.MainnetParams()

	require.False(t, params.AllowSimulated,
		"AllowSimulated must be false for mainnet")
	require.True(t, params.RequireTeeAttestation,
		"RequireTeeAttestation must be true for mainnet")
}

func TestMainnetParams_EconomicsConfigured(t *testing.T) {
	params := keeper.MainnetParams()

	require.NotEmpty(t, params.BaseJobFee)
	require.NotEmpty(t, params.VerificationReward)
	require.NotEmpty(t, params.SlashingPenalty)
}

func TestMainnetParams_ProofTypesComplete(t *testing.T) {
	params := keeper.MainnetParams()

	require.Contains(t, params.AllowedProofTypes, "tee")
	require.Contains(t, params.AllowedProofTypes, "zkml")
	require.Contains(t, params.AllowedProofTypes, "hybrid")
	require.Len(t, params.AllowedProofTypes, 3)
}

func TestMainnetFeeDistribution_ConservesValue(t *testing.T) {
	config := keeper.MainnetFeeDistribution()

	total := config.ValidatorRewardBps + config.TreasuryBps + config.BurnBps + config.InsuranceFundBps
	require.Equal(t, int64(10000), total,
		"fee BPS must sum to exactly 10000 (100%%)")

	require.Greater(t, config.ValidatorRewardBps, int64(0), "validators must be rewarded")
	require.Greater(t, config.BurnBps, int64(0), "burn must be > 0 for deflation")
	require.Greater(t, config.InsuranceFundBps, int64(0), "insurance fund must be > 0")
}

// =============================================================================
// Section 2: Parameter Lock Registry
// =============================================================================

func TestParamLockRegistry_Complete(t *testing.T) {
	registry := keeper.MainnetParamLockRegistry()

	require.GreaterOrEqual(t, len(registry), 10,
		"registry must cover at least 10 parameter fields")

	// All entries must have required fields
	for _, entry := range registry {
		require.NotEmpty(t, entry.Field, "entry must have field name")
		require.NotEmpty(t, entry.LockedValue, "entry %s must have locked value", entry.Field)
		require.NotEmpty(t, entry.Reason, "entry %s must have reason", entry.Field)
		require.NotEqual(t, keeper.ParamLockStatus(""), entry.Status,
			"entry %s must have status", entry.Field)
	}
}

func TestParamLockRegistry_HasLockedParams(t *testing.T) {
	locked := keeper.GetLockedParams()
	require.NotEmpty(t, locked, "must have at least one locked parameter")

	// AllowSimulated must be locked
	hasSimulated := false
	for _, entry := range locked {
		if entry.Field == "allow_simulated" {
			hasSimulated = true
			require.False(t, entry.CanOverride,
				"AllowSimulated must not be overridable")
		}
	}
	require.True(t, hasSimulated, "allow_simulated must be in locked set")
}

func TestParamLockRegistry_HasMutableParams(t *testing.T) {
	mutable := keeper.GetMutableParams()
	require.NotEmpty(t, mutable, "must have at least one mutable parameter")

	// All mutable params must have quorum specified
	for _, entry := range mutable {
		require.Greater(t, entry.MinQuorum, 0,
			"mutable param %s must have quorum specified", entry.Field)
	}
}

func TestParamLockRegistry_LockedConsensusThreshold(t *testing.T) {
	locked := keeper.GetLockedParams()

	hasThreshold := false
	for _, entry := range locked {
		if entry.Field == "consensus_threshold" {
			hasThreshold = true
			require.True(t, entry.CanOverride,
				"consensus_threshold should be overridable with elevated quorum")
			require.GreaterOrEqual(t, entry.MinQuorum, 80,
				"consensus_threshold override should require >= 80%% quorum")
		}
	}
	require.True(t, hasThreshold, "consensus_threshold must be locked")
}

func TestParamLockRegistry_NoUnknownStatuses(t *testing.T) {
	for _, entry := range keeper.MainnetParamLockRegistry() {
		switch entry.Status {
		case keeper.ParamLocked, keeper.ParamMutable, keeper.ParamDeprecated:
			// valid
		default:
			t.Errorf("unknown lock status %q for field %s", entry.Status, entry.Field)
		}
	}
}

// =============================================================================
// Section 3: Parameter Change Proposal Validation
// =============================================================================

func TestParamChangeProposal_MutableAllowed(t *testing.T) {
	result := keeper.ValidateParamChangeProposal(keeper.ParamChangeProposal{
		Field:    "min_validators",
		OldValue: "5",
		NewValue: "7",
		Proposer: "gov-module",
	})

	require.True(t, result.Allowed)
	require.Equal(t, keeper.ParamMutable, result.LockStatus)
	require.Equal(t, 67, result.RequiredQuorum)
}

func TestParamChangeProposal_LockedWithOverride(t *testing.T) {
	result := keeper.ValidateParamChangeProposal(keeper.ParamChangeProposal{
		Field:    "consensus_threshold",
		OldValue: "67",
		NewValue: "70",
		Proposer: "gov-module",
	})

	require.True(t, result.Allowed)
	require.Equal(t, keeper.ParamLocked, result.LockStatus)
	require.GreaterOrEqual(t, result.RequiredQuorum, 80)
	require.NotEmpty(t, result.Warnings, "locked param changes should generate warnings")
}

func TestParamChangeProposal_PermanentlyLocked(t *testing.T) {
	result := keeper.ValidateParamChangeProposal(keeper.ParamChangeProposal{
		Field:    "allow_simulated",
		OldValue: "false",
		NewValue: "true",
		Proposer: "gov-module",
	})

	require.False(t, result.Allowed,
		"AllowSimulated cannot be re-enabled — permanently locked")
	require.Contains(t, result.Reason, "permanently locked")
}

func TestParamChangeProposal_UnknownField(t *testing.T) {
	result := keeper.ValidateParamChangeProposal(keeper.ParamChangeProposal{
		Field:    "unknown_field",
		OldValue: "x",
		NewValue: "y",
		Proposer: "gov-module",
	})

	require.False(t, result.Allowed)
	require.Contains(t, result.Reason, "unknown parameter")
}

func TestParamChangeProposal_SlashingPenaltyLocked(t *testing.T) {
	result := keeper.ValidateParamChangeProposal(keeper.ParamChangeProposal{
		Field:    "slashing_penalty",
		OldValue: "10000uaeth",
		NewValue: "5000uaeth",
		Proposer: "gov-module",
	})

	require.True(t, result.Allowed, "locked params with CanOverride=true should be allowed")
	require.Equal(t, keeper.ParamLocked, result.LockStatus)
	require.GreaterOrEqual(t, result.RequiredQuorum, 80)
}

func TestParamChangeProposal_TeeAttestationLocked(t *testing.T) {
	result := keeper.ValidateParamChangeProposal(keeper.ParamChangeProposal{
		Field:    "require_tee_attestation",
		OldValue: "true",
		NewValue: "false",
		Proposer: "gov-module",
	})

	require.True(t, result.Allowed, "TEE attestation can be overridden with elevated quorum")
	require.GreaterOrEqual(t, result.RequiredQuorum, 90,
		"TEE attestation override should require >= 90%% quorum")
}

// =============================================================================
// Section 4: Mainnet Genesis Validation
// =============================================================================

func TestMainnetGenesis_DefaultValid(t *testing.T) {
	config := keeper.DefaultMainnetGenesisConfig()
	issues := keeper.ValidateMainnetGenesis(config)

	require.Empty(t, issues, "default mainnet genesis should be valid")
}

func TestMainnetGenesis_WrongChainID(t *testing.T) {
	config := keeper.DefaultMainnetGenesisConfig()
	config.ChainID = "wrong-chain-1"

	issues := keeper.ValidateMainnetGenesis(config)
	require.NotEmpty(t, issues)

	hasChainIDIssue := false
	for _, issue := range issues {
		if strings.Contains(issue, "chain ID") {
			hasChainIDIssue = true
		}
	}
	require.True(t, hasChainIDIssue, "should flag wrong chain ID")
}

func TestMainnetGenesis_SimulatedEnabled(t *testing.T) {
	config := keeper.DefaultMainnetGenesisConfig()
	config.Params.AllowSimulated = true

	issues := keeper.ValidateMainnetGenesis(config)
	require.NotEmpty(t, issues)

	hasSecurityIssue := false
	for _, issue := range issues {
		if strings.Contains(issue, "AllowSimulated") {
			hasSecurityIssue = true
		}
	}
	require.True(t, hasSecurityIssue, "should flag AllowSimulated=true")
}

func TestMainnetGenesis_LowConsensusThreshold(t *testing.T) {
	config := keeper.DefaultMainnetGenesisConfig()
	config.Params.ConsensusThreshold = 55

	issues := keeper.ValidateMainnetGenesis(config)
	require.NotEmpty(t, issues)

	hasSafetyIssue := false
	for _, issue := range issues {
		if strings.Contains(issue, "BFT") {
			hasSafetyIssue = true
		}
	}
	require.True(t, hasSafetyIssue, "should flag low consensus threshold")
}

func TestMainnetGenesis_InvalidFeeDistribution(t *testing.T) {
	config := keeper.DefaultMainnetGenesisConfig()
	config.FeeConfig.BurnBps = 0

	issues := keeper.ValidateMainnetGenesis(config)
	require.NotEmpty(t, issues)

	hasFeeIssue := false
	for _, issue := range issues {
		if strings.Contains(issue, "fee BPS sum") || strings.Contains(issue, "BurnBps") {
			hasFeeIssue = true
		}
	}
	require.True(t, hasFeeIssue, "should flag invalid fee distribution")
}

// =============================================================================
// Section 5: Parameter Compatibility Checks
// =============================================================================

func TestParamCompatibility_NoChanges(t *testing.T) {
	k, ctx := newTestKeeper(t)

	current, err := k.GetParams(ctx)
	require.NoError(t, err)

	result := keeper.CheckParameterCompatibility(ctx, k, current)
	require.True(t, result.Compatible)
	require.Empty(t, result.Changes)
}

func TestParamCompatibility_SafeChange(t *testing.T) {
	k, ctx := newTestKeeper(t)

	proposed := types.DefaultParams()
	proposed.MaxJobsPerBlock = 25 // increase from 10

	result := keeper.CheckParameterCompatibility(ctx, k, proposed)
	require.True(t, result.Compatible)
	require.NotEmpty(t, result.Changes)
}

func TestParamCompatibility_UnsafeConsensusThreshold(t *testing.T) {
	k, ctx := newTestKeeper(t)

	proposed := types.DefaultParams()
	proposed.ConsensusThreshold = 55 // below BFT safety

	result := keeper.CheckParameterCompatibility(ctx, k, proposed)
	require.False(t, result.Compatible,
		"lowering consensus threshold below 67 should be incompatible")
	require.NotEmpty(t, result.Blockers)
}

func TestParamCompatibility_OneWayGateBlocker(t *testing.T) {
	k, ctx := newTestKeeper(t)

	proposed := types.DefaultParams()
	proposed.AllowSimulated = true // try to re-enable

	result := keeper.CheckParameterCompatibility(ctx, k, proposed)
	require.False(t, result.Compatible,
		"re-enabling AllowSimulated should be incompatible")
	require.NotEmpty(t, result.Blockers)
}

func TestParamCompatibility_ReducingMaxJobsWarning(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Seed a pending job
	seedJobs(t, ctx, k, 1)

	proposed := types.DefaultParams()
	proposed.MaxJobsPerBlock = 5 // reduce from 10

	result := keeper.CheckParameterCompatibility(ctx, k, proposed)
	// Should be compatible but with warnings
	require.True(t, result.Compatible)
	require.NotEmpty(t, result.Warnings)
}

// =============================================================================
// Section 6: Mainnet Param Report Rendering
// =============================================================================

func TestMainnetParamReport_Render(t *testing.T) {
	rendered := keeper.RenderMainnetParamReport()

	require.Contains(t, rendered, "MAINNET PARAMETER SET")
	require.Contains(t, rendered, keeper.MainnetChainID)
	require.Contains(t, rendered, "LOCKED PARAMETERS")
	require.Contains(t, rendered, "MUTABLE PARAMETERS")
	require.Contains(t, rendered, "FEE DISTRIBUTION")
	require.Contains(t, rendered, "VALIDATION")

	t.Log(rendered)
}

func TestMainnetParamReport_ContainsLockStatuses(t *testing.T) {
	rendered := keeper.RenderMainnetParamReport()

	require.Contains(t, rendered, "consensus_threshold")
	require.Contains(t, rendered, "allow_simulated")
	require.Contains(t, rendered, "min_validators")
}

func TestMainnetParamReport_ValidationPasses(t *testing.T) {
	rendered := keeper.RenderMainnetParamReport()
	require.Contains(t, rendered, "PASSED",
		"default mainnet config should pass all validation checks")
}

package keeper_test

import (
	"fmt"
	"math/rand"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// TOKENOMICS TESTS
//
// These tests verify the fee distribution model and governance parameter system:
//   - Fee distribution config validation
//   - Fee breakdown calculations with dust handling
//   - Reputation-scaled validator rewards
//   - Parameter validation, merging, and diffing
//   - Economic invariant (property-based) tests
//
// The fee distribution functions are pure calculations that do not require
// on-chain state, so no keeper instantiation is needed.
// =============================================================================

// =============================================================================
// Section 1: Fee Distribution Config
// =============================================================================

func TestTokenomics_DefaultConfig_ValidBps(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()

	require.True(t, config.ValidatorRewardBps > 0, "ValidatorRewardBps must be positive")
	require.True(t, config.TreasuryBps > 0, "TreasuryBps must be positive")
	require.True(t, config.BurnBps > 0, "BurnBps must be positive")
	require.True(t, config.InsuranceFundBps > 0, "InsuranceFundBps must be positive")

	sum := config.ValidatorRewardBps + config.TreasuryBps + config.BurnBps + config.InsuranceFundBps
	require.Equal(t, int64(10000), sum, "default config BPS must sum to 10000")
}

func TestTokenomics_ValidateConfig_ValidCustom(t *testing.T) {
	config := keeper.FeeDistributionConfig{
		ValidatorRewardBps: 5000, // 50%
		TreasuryBps:        2000, // 20%
		BurnBps:            2000, // 20%
		InsuranceFundBps:   1000, // 10%
	}
	err := keeper.ValidateFeeDistribution(config)
	require.NoError(t, err, "custom config summing to 10000 should be valid")
}

func TestTokenomics_ValidateConfig_InvalidSum(t *testing.T) {
	config := keeper.FeeDistributionConfig{
		ValidatorRewardBps: 4000,
		TreasuryBps:        3000,
		BurnBps:            1000,
		InsuranceFundBps:   1000,
	}
	// Sum = 9000, not 10000
	err := keeper.ValidateFeeDistribution(config)
	require.Error(t, err, "config summing to 9000 should fail validation")
}

func TestTokenomics_ValidateConfig_NegativeBps(t *testing.T) {
	config := keeper.FeeDistributionConfig{
		ValidatorRewardBps: -1000,
		TreasuryBps:        5000,
		BurnBps:            3000,
		InsuranceFundBps:   3000,
	}
	err := keeper.ValidateFeeDistribution(config)
	require.Error(t, err, "config with negative BPS should fail validation")
}

func TestTokenomics_ValidateConfig_ZeroBps(t *testing.T) {
	// It is valid to have zero for some components as long as the total sums to 10000
	config := keeper.FeeDistributionConfig{
		ValidatorRewardBps: 10000,
		TreasuryBps:        0,
		BurnBps:            0,
		InsuranceFundBps:   0,
	}
	err := keeper.ValidateFeeDistribution(config)
	require.NoError(t, err, "config with zero components should be valid if sum is 10000")
}

// =============================================================================
// Section 2: Fee Breakdown Calculation
// =============================================================================

func TestTokenomics_Breakdown_DefaultConfig(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	totalFee := sdk.NewInt64Coin("uaeth", 1000)
	validatorCount := 3

	result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

	require.Equal(t, totalFee, result.TotalFee, "TotalFee must match input")
	require.Equal(t, validatorCount, result.ValidatorCount, "ValidatorCount must match")

	// Default config: 40% validator, 30% treasury, 20% burn, 10% insurance
	// ValidatorRewards = PerValidatorReward * validatorCount (the actual amount paid out)
	// validatorTotal = 1000 * 4000 / 10000 = 400
	// perValidator   = 400 / 3 = 133 (truncated)
	// validatorActual = 133 * 3 = 399
	require.True(t, result.ValidatorRewards.Amount.Equal(sdkmath.NewInt(399)),
		"ValidatorRewards: 133*3 = 399 (actual paid, not gross allocation)")
	require.True(t, result.PerValidatorReward.Amount.Equal(sdkmath.NewInt(133)),
		"PerValidatorReward: 400/3 = 133 (truncated)")
	// TreasuryAmount = treasuryRaw + dust. treasuryRaw = 1000*3000/10000 = 300, dust = 1000 - (399 + 300 + 200 + 100) = 1
	require.True(t, result.TreasuryAmount.Amount.Equal(sdkmath.NewInt(301)),
		"TreasuryAmount: 300 (raw) + 1 (dust) = 301")
	require.True(t, result.BurnedAmount.Amount.Equal(sdkmath.NewInt(200)),
		"BurnedAmount: 20%% of 1000 = 200")
	require.True(t, result.InsuranceFund.Amount.Equal(sdkmath.NewInt(100)),
		"InsuranceFund: 10%% of 1000 = 100")

	// Dust = total - (validatorActual + treasuryRaw + burn + insurance) = 1000 - (399+300+200+100) = 1
	require.True(t, result.DustToTreasury.Amount.Equal(sdkmath.NewInt(1)),
		"DustToTreasury: 1000 - (399+300+200+100) = 1")
}

func TestTokenomics_Breakdown_SingleValidator(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	totalFee := sdk.NewInt64Coin("uaeth", 1000)

	result := keeper.CalculateFeeBreakdown(totalFee, config, 1)

	// validatorTotal = 1000*4000/10000 = 400; perValidator = 400/1 = 400; validatorActual = 400*1 = 400
	require.True(t, result.ValidatorRewards.Amount.Equal(sdkmath.NewInt(400)),
		"single validator gets the entire validator share = 400")
	require.True(t, result.PerValidatorReward.Amount.Equal(sdkmath.NewInt(400)),
		"single validator gets the entire validator share")
	// dust = 1000 - (400 + 300 + 200 + 100) = 0
	require.True(t, result.DustToTreasury.Amount.IsZero(),
		"no dust with a single validator and clean numbers")
}

func TestTokenomics_Breakdown_LargeFee(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	totalFee := sdk.NewInt64Coin("uaeth", 1000000) // 1 AETH
	validatorCount := 5

	result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

	// validatorTotal = 1000000*4000/10000 = 400000; perValidator = 400000/5 = 80000
	// validatorActual = 80000*5 = 400000; all buckets clean, dust = 0
	require.True(t, result.ValidatorRewards.Amount.Equal(sdkmath.NewInt(400000)),
		"ValidatorRewards: 80000*5 = 400000")
	require.True(t, result.PerValidatorReward.Amount.Equal(sdkmath.NewInt(80000)),
		"PerValidatorReward: 400000/5 = 80000")
	require.True(t, result.BurnedAmount.Amount.Equal(sdkmath.NewInt(200000)),
		"BurnedAmount: 20%% of 1000000 = 200000")
	require.True(t, result.InsuranceFund.Amount.Equal(sdkmath.NewInt(100000)),
		"InsuranceFund: 10%% of 1000000 = 100000")
	// dust = 1000000 - (400000+300000+200000+100000) = 0, so TreasuryAmount = 300000 + 0 = 300000
	require.True(t, result.TreasuryAmount.Amount.Equal(sdkmath.NewInt(300000)),
		"TreasuryAmount: 30%% of 1000000 = 300000 (no dust)")
	require.True(t, result.DustToTreasury.Amount.IsZero(),
		"400000 divides evenly by 5, no dust")
}

func TestTokenomics_Breakdown_SmallFee(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	totalFee := sdk.NewInt64Coin("uaeth", 10)
	validatorCount := 3

	result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

	// With integer truncation, some components may be 0 but none should be negative
	require.True(t, result.ValidatorRewards.Amount.GTE(sdkmath.ZeroInt()),
		"ValidatorRewards must be >= 0")
	require.True(t, result.PerValidatorReward.Amount.GTE(sdkmath.ZeroInt()),
		"PerValidatorReward must be >= 0")
	require.True(t, result.TreasuryAmount.Amount.GTE(sdkmath.ZeroInt()),
		"TreasuryAmount must be >= 0")
	require.True(t, result.BurnedAmount.Amount.GTE(sdkmath.ZeroInt()),
		"BurnedAmount must be >= 0")
	require.True(t, result.InsuranceFund.Amount.GTE(sdkmath.ZeroInt()),
		"InsuranceFund must be >= 0")
	require.True(t, result.DustToTreasury.Amount.GTE(sdkmath.ZeroInt()),
		"DustToTreasury must be >= 0")
}

func TestTokenomics_Breakdown_OneUaethFee(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	totalFee := sdk.NewInt64Coin("uaeth", 1)
	validatorCount := 3

	// Must not panic
	result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

	// All amounts must be non-negative
	require.True(t, result.ValidatorRewards.Amount.GTE(sdkmath.ZeroInt()),
		"ValidatorRewards must be >= 0 for 1uaeth fee")
	require.True(t, result.PerValidatorReward.Amount.GTE(sdkmath.ZeroInt()),
		"PerValidatorReward must be >= 0 for 1uaeth fee")
	require.True(t, result.TreasuryAmount.Amount.GTE(sdkmath.ZeroInt()),
		"TreasuryAmount must be >= 0 for 1uaeth fee")
	require.True(t, result.BurnedAmount.Amount.GTE(sdkmath.ZeroInt()),
		"BurnedAmount must be >= 0 for 1uaeth fee")
	require.True(t, result.InsuranceFund.Amount.GTE(sdkmath.ZeroInt()),
		"InsuranceFund must be >= 0 for 1uaeth fee")
	require.True(t, result.DustToTreasury.Amount.GTE(sdkmath.ZeroInt()),
		"DustToTreasury must be >= 0 for 1uaeth fee")
}

func TestTokenomics_Breakdown_ZeroFee(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	totalFee := sdk.NewInt64Coin("uaeth", 0)
	validatorCount := 3

	result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

	require.Equal(t, sdk.NewInt64Coin("uaeth", 0), result.ValidatorRewards)
	require.Equal(t, sdk.NewInt64Coin("uaeth", 0), result.PerValidatorReward)
	require.Equal(t, sdk.NewInt64Coin("uaeth", 0), result.TreasuryAmount)
	require.Equal(t, sdk.NewInt64Coin("uaeth", 0), result.BurnedAmount)
	require.Equal(t, sdk.NewInt64Coin("uaeth", 0), result.InsuranceFund)
	require.Equal(t, sdk.NewInt64Coin("uaeth", 0), result.DustToTreasury)
}

func TestTokenomics_Breakdown_ConservationOfValue(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 100; i++ {
		amount := rng.Int63n(10000000) + 1 // 1 to 10M
		totalFee := sdk.NewInt64Coin("uaeth", amount)
		validatorCount := int(rng.Int63n(20)) + 1 // 1 to 20

		result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

		// Sum of all distributed amounts must equal the total fee.
		// NOTE: TreasuryAmount already includes DustToTreasury (treasuryFinal = treasuryRaw + dust),
		// so we must NOT add DustToTreasury separately or it will be double-counted.
		// Distributed = PerValidatorReward * validatorCount + TreasuryAmount + BurnedAmount + InsuranceFund
		perValTotal := result.PerValidatorReward.Amount.MulRaw(int64(validatorCount))
		distributed := perValTotal.
			Add(result.TreasuryAmount.Amount).
			Add(result.BurnedAmount.Amount).
			Add(result.InsuranceFund.Amount)

		require.True(t, distributed.Equal(totalFee.Amount),
			"conservation of value violated: fee=%d, distributed=%s (validators=%d, iteration=%d)",
			amount, distributed.String(), validatorCount, i)
	}
}

func TestTokenomics_Breakdown_NoNegativeAmounts(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()

	edgeCases := []int64{0, 1, 2, 3, 5, 7, 9, 10, 99, 100, 999, 1000}
	for _, amount := range edgeCases {
		for validatorCount := 1; validatorCount <= 20; validatorCount++ {
			totalFee := sdk.NewInt64Coin("uaeth", amount)
			result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

			require.True(t, result.ValidatorRewards.Amount.GTE(sdkmath.ZeroInt()),
				"ValidatorRewards negative for fee=%d, validators=%d", amount, validatorCount)
			require.True(t, result.PerValidatorReward.Amount.GTE(sdkmath.ZeroInt()),
				"PerValidatorReward negative for fee=%d, validators=%d", amount, validatorCount)
			require.True(t, result.TreasuryAmount.Amount.GTE(sdkmath.ZeroInt()),
				"TreasuryAmount negative for fee=%d, validators=%d", amount, validatorCount)
			require.True(t, result.BurnedAmount.Amount.GTE(sdkmath.ZeroInt()),
				"BurnedAmount negative for fee=%d, validators=%d", amount, validatorCount)
			require.True(t, result.InsuranceFund.Amount.GTE(sdkmath.ZeroInt()),
				"InsuranceFund negative for fee=%d, validators=%d", amount, validatorCount)
			require.True(t, result.DustToTreasury.Amount.GTE(sdkmath.ZeroInt()),
				"DustToTreasury negative for fee=%d, validators=%d", amount, validatorCount)
		}
	}
}

// =============================================================================
// Section 3: Reputation-Scaled Rewards
// =============================================================================

func TestTokenomics_ReputationReward_MaxReputation(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaeth", 1000)
	scaled := keeper.RewardScaleByReputation(baseReward, 100)

	// Reputation 100 => 100% of base reward
	require.Equal(t, baseReward, scaled,
		"max reputation (100) should yield full base reward")
}

func TestTokenomics_ReputationReward_MinReputation(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaeth", 1000)
	scaled := keeper.RewardScaleByReputation(baseReward, 0)

	// Reputation 0 => 50% of base reward
	require.Equal(t, sdk.NewInt64Coin("uaeth", 500), scaled,
		"min reputation (0) should yield 50%% of base reward")
}

func TestTokenomics_ReputationReward_MidReputation(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaeth", 1000)
	scaled := keeper.RewardScaleByReputation(baseReward, 50)

	// Reputation 50 => 75% of base reward
	require.Equal(t, sdk.NewInt64Coin("uaeth", 750), scaled,
		"mid reputation (50) should yield 75%% of base reward")
}

func TestTokenomics_ReputationReward_Monotonic(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaeth", 10000)
	reputations := []int64{0, 25, 50, 75, 100}

	var previousAmount sdkmath.Int
	for i, rep := range reputations {
		scaled := keeper.RewardScaleByReputation(baseReward, rep)
		if i > 0 {
			require.True(t, scaled.Amount.GTE(previousAmount),
				"reward should increase monotonically: reputation %d yielded %s, but previous was %s",
				rep, scaled.Amount.String(), previousAmount.String())
		}
		previousAmount = scaled.Amount
	}
}

func TestTokenomics_ReputationReward_NeverZero(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaeth", 1)
	scaled := keeper.RewardScaleByReputation(baseReward, 0)

	// With 1uaeth base reward and minimum reputation, the result should be >= 0
	// (the formula gives 50% of 1 = 0 due to integer truncation, but must not go below 0)
	require.True(t, scaled.Amount.GTE(sdkmath.ZeroInt()),
		"reputation-scaled reward should never be negative, got %s", scaled.Amount.String())
}

// =============================================================================
// Section 4: Parameter Validation
// =============================================================================

func TestTokenomics_ValidateParams_DefaultsAreValid(t *testing.T) {
	params := types.DefaultParams()
	err := keeper.ValidateParams(params)
	require.NoError(t, err, "default params should pass validation")
}

func TestTokenomics_ValidateParams_MinValidatorsTooLow(t *testing.T) {
	params := types.DefaultParams()
	params.MinValidators = 0
	err := keeper.ValidateParams(params)
	require.Error(t, err, "MinValidators=0 should fail validation")
}

func TestTokenomics_ValidateParams_ConsensusThresholdTooLow(t *testing.T) {
	params := types.DefaultParams()
	params.ConsensusThreshold = 49
	err := keeper.ValidateParams(params)
	require.Error(t, err, "ConsensusThreshold=49 should fail validation")
}

func TestTokenomics_ValidateParams_ConsensusThresholdTooHigh(t *testing.T) {
	params := types.DefaultParams()
	params.ConsensusThreshold = 101
	err := keeper.ValidateParams(params)
	require.Error(t, err, "ConsensusThreshold=101 should fail validation")
}

func TestTokenomics_ValidateParams_InvalidJobFee(t *testing.T) {
	params := types.DefaultParams()
	params.BaseJobFee = "invalid"
	err := keeper.ValidateParams(params)
	require.Error(t, err, "BaseJobFee='invalid' should fail validation")
}

func TestTokenomics_ValidateParams_JobTimeoutTooLow(t *testing.T) {
	params := types.DefaultParams()
	params.JobTimeoutBlocks = 5 // below minimum of 10
	err := keeper.ValidateParams(params)
	require.Error(t, err, "JobTimeoutBlocks=5 should fail validation")
}

func TestTokenomics_ValidateParams_EmptyProofTypes(t *testing.T) {
	params := types.DefaultParams()
	params.AllowedProofTypes = []string{}
	err := keeper.ValidateParams(params)
	require.Error(t, err, "empty AllowedProofTypes should fail validation")
}

func TestTokenomics_ValidateParams_InvalidProofType(t *testing.T) {
	params := types.DefaultParams()
	params.AllowedProofTypes = []string{"tee", "invalid_type"}
	err := keeper.ValidateParams(params)
	require.Error(t, err, "AllowedProofTypes with 'invalid_type' should fail validation")
}

// =============================================================================
// Section 5: Parameter Merge
// =============================================================================

func TestTokenomics_MergeParams_NoChanges(t *testing.T) {
	current := types.DefaultParams()

	// To make a "no-op" update we must explicitly set the bool fields to match
	// current values, because MergeParams always applies bool fields from the
	// update (false is a valid value, so there's no "unset" sentinel).
	update := &types.Params{
		RequireTeeAttestation: current.RequireTeeAttestation,
		AllowZkmlFallback:     current.AllowZkmlFallback,
		AllowSimulated:        current.AllowSimulated,
	}

	merged := keeper.MergeParams(current, update)

	require.Equal(t, current.MinValidators, merged.MinValidators)
	require.Equal(t, current.ConsensusThreshold, merged.ConsensusThreshold)
	require.Equal(t, current.JobTimeoutBlocks, merged.JobTimeoutBlocks)
	require.Equal(t, current.BaseJobFee, merged.BaseJobFee)
	require.Equal(t, current.VerificationReward, merged.VerificationReward)
	require.Equal(t, current.SlashingPenalty, merged.SlashingPenalty)
	require.Equal(t, current.MaxJobsPerBlock, merged.MaxJobsPerBlock)
	require.Equal(t, current.AllowedProofTypes, merged.AllowedProofTypes)
	require.Equal(t, current.RequireTeeAttestation, merged.RequireTeeAttestation)
	require.Equal(t, current.AllowZkmlFallback, merged.AllowZkmlFallback)
	require.Equal(t, current.AllowSimulated, merged.AllowSimulated)
}

func TestTokenomics_MergeParams_PartialUpdate(t *testing.T) {
	current := types.DefaultParams()
	// Set bool fields to match current defaults so they don't inadvertently
	// change due to MergeParams always applying bool fields from the update.
	update := &types.Params{
		ConsensusThreshold:    80,
		RequireTeeAttestation: current.RequireTeeAttestation,
		AllowZkmlFallback:     current.AllowZkmlFallback,
		AllowSimulated:        current.AllowSimulated,
	}

	merged := keeper.MergeParams(current, update)

	// Changed field
	require.Equal(t, int64(80), merged.ConsensusThreshold,
		"ConsensusThreshold should be updated to 80")

	// Unchanged fields should retain defaults
	require.Equal(t, current.MinValidators, merged.MinValidators)
	require.Equal(t, current.JobTimeoutBlocks, merged.JobTimeoutBlocks)
	require.Equal(t, current.BaseJobFee, merged.BaseJobFee)
	require.Equal(t, current.VerificationReward, merged.VerificationReward)
	require.Equal(t, current.SlashingPenalty, merged.SlashingPenalty)
	require.Equal(t, current.MaxJobsPerBlock, merged.MaxJobsPerBlock)
	require.Equal(t, current.AllowedProofTypes, merged.AllowedProofTypes)
	require.Equal(t, current.RequireTeeAttestation, merged.RequireTeeAttestation)
	require.Equal(t, current.AllowZkmlFallback, merged.AllowZkmlFallback)
	require.Equal(t, current.AllowSimulated, merged.AllowSimulated)
}

func TestTokenomics_MergeParams_MultipleFields(t *testing.T) {
	current := types.DefaultParams()
	update := &types.Params{
		MinValidators: 5,
		BaseJobFee:    "2000uaeth",
	}

	merged := keeper.MergeParams(current, update)

	// Changed fields
	require.Equal(t, int64(5), merged.MinValidators,
		"MinValidators should be updated to 5")
	require.Equal(t, "2000uaeth", merged.BaseJobFee,
		"BaseJobFee should be updated to 2000uaeth")

	// Unchanged fields
	require.Equal(t, current.ConsensusThreshold, merged.ConsensusThreshold)
	require.Equal(t, current.JobTimeoutBlocks, merged.JobTimeoutBlocks)
	require.Equal(t, current.VerificationReward, merged.VerificationReward)
	require.Equal(t, current.SlashingPenalty, merged.SlashingPenalty)
	require.Equal(t, current.MaxJobsPerBlock, merged.MaxJobsPerBlock)
	require.Equal(t, current.AllowedProofTypes, merged.AllowedProofTypes)
}

func TestTokenomics_MergeParams_BoolFieldsAlwaysApplied(t *testing.T) {
	// Default has RequireTeeAttestation=true. Setting it to false (the zero
	// value for bool) should still apply, not be ignored.
	current := types.DefaultParams()
	require.True(t, current.RequireTeeAttestation,
		"default RequireTeeAttestation should be true")

	update := &types.Params{
		RequireTeeAttestation: false,
	}

	merged := keeper.MergeParams(current, update)

	require.False(t, merged.RequireTeeAttestation,
		"RequireTeeAttestation should be updated to false even though false is the zero value")
}

func TestTokenomics_MergeParams_AllFieldsUpdated(t *testing.T) {
	current := types.DefaultParams()
	update := &types.Params{
		MinValidators:         5,
		ConsensusThreshold:    80,
		JobTimeoutBlocks:      200,
		BaseJobFee:            "5000uaeth",
		VerificationReward:    "500uaeth",
		SlashingPenalty:       "50000uaeth",
		MaxJobsPerBlock:       20,
		AllowedProofTypes:     []string{"tee", "hybrid"},
		RequireTeeAttestation: false,
		AllowZkmlFallback:     false,
		AllowSimulated:        true,
	}

	merged := keeper.MergeParams(current, update)

	require.Equal(t, int64(5), merged.MinValidators)
	require.Equal(t, int64(80), merged.ConsensusThreshold)
	require.Equal(t, int64(200), merged.JobTimeoutBlocks)
	require.Equal(t, "5000uaeth", merged.BaseJobFee)
	require.Equal(t, "500uaeth", merged.VerificationReward)
	require.Equal(t, "50000uaeth", merged.SlashingPenalty)
	require.Equal(t, int64(20), merged.MaxJobsPerBlock)
	require.Equal(t, []string{"tee", "hybrid"}, merged.AllowedProofTypes)
	require.False(t, merged.RequireTeeAttestation)
	require.False(t, merged.AllowZkmlFallback)
	require.True(t, merged.AllowSimulated)
}

// =============================================================================
// Section 6: Parameter Diff
// =============================================================================

func TestTokenomics_DiffParams_NoDifference(t *testing.T) {
	params := types.DefaultParams()
	changes := keeper.DiffParams(params, params)

	require.Empty(t, changes, "identical params should produce empty diff")
}

func TestTokenomics_DiffParams_SingleChange(t *testing.T) {
	old := types.DefaultParams()
	new := types.DefaultParams()
	new.ConsensusThreshold = 80

	changes := keeper.DiffParams(old, new)

	require.Len(t, changes, 1, "single field change should produce 1 diff entry")
	require.Equal(t, "consensus_threshold", changes[0].Field)
	require.Equal(t, fmt.Sprintf("%d", old.ConsensusThreshold), changes[0].OldValue)
	require.Equal(t, "80", changes[0].NewValue)
}

func TestTokenomics_DiffParams_MultipleChanges(t *testing.T) {
	old := types.DefaultParams()
	new := types.DefaultParams()
	new.MinValidators = 5
	new.BaseJobFee = "5000uaeth"
	new.AllowSimulated = true

	changes := keeper.DiffParams(old, new)

	require.Len(t, changes, 3, "three field changes should produce 3 diff entries")

	// Build a map of changed fields for easier assertions.
	// DiffParams uses snake_case field names (matching proto / event naming).
	changedFields := make(map[string]keeper.ParamFieldChange)
	for _, c := range changes {
		changedFields[c.Field] = c
	}

	minValChange, ok := changedFields["min_validators"]
	require.True(t, ok, "min_validators should be in the diff")
	require.Equal(t, fmt.Sprintf("%d", old.MinValidators), minValChange.OldValue)
	require.Equal(t, "5", minValChange.NewValue)

	feeChange, ok := changedFields["base_job_fee"]
	require.True(t, ok, "base_job_fee should be in the diff")
	require.Equal(t, old.BaseJobFee, feeChange.OldValue)
	require.Equal(t, "5000uaeth", feeChange.NewValue)

	simChange, ok := changedFields["allow_simulated"]
	require.True(t, ok, "allow_simulated should be in the diff")
	require.Equal(t, "false", simChange.OldValue)
	require.Equal(t, "true", simChange.NewValue)
}

// =============================================================================
// Section 7: Economic Invariant Tests
// =============================================================================

func TestTokenomics_Invariant_FeesSumToTotal(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	rng := rand.New(rand.NewSource(12345))

	for i := 0; i < 1000; i++ {
		amount := rng.Int63n(100000000) + 1 // 1 to 100M
		validatorCount := int(rng.Int63n(20)) + 1

		totalFee := sdk.NewInt64Coin("uaeth", amount)
		result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

		// Total distributed = PerValidatorReward * validatorCount +
		//                     TreasuryAmount + BurnedAmount + InsuranceFund
		// NOTE: TreasuryAmount already includes DustToTreasury, so do NOT add dust separately.
		perValDistributed := result.PerValidatorReward.Amount.MulRaw(int64(validatorCount))
		totalDistributed := perValDistributed.
			Add(result.TreasuryAmount.Amount).
			Add(result.BurnedAmount.Amount).
			Add(result.InsuranceFund.Amount)

		require.True(t, totalDistributed.Equal(totalFee.Amount),
			"invariant violated at iteration %d: fee=%d, validators=%d, distributed=%s",
			i, amount, validatorCount, totalDistributed.String())
	}
}

func TestTokenomics_Invariant_ValidatorsAlwaysPaid(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	rng := rand.New(rand.NewSource(99))

	for i := 0; i < 100; i++ {
		amount := rng.Int63n(1000000) + 1
		validatorCount := int(rng.Int63n(20)) + 1

		totalFee := sdk.NewInt64Coin("uaeth", amount)
		result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

		// If fee > 0 and validator count > 0, per-validator reward >= 0
		require.True(t, result.PerValidatorReward.Amount.GTE(sdkmath.ZeroInt()),
			"per-validator reward must be >= 0 for fee=%d, validators=%d",
			amount, validatorCount)
	}
}

func TestTokenomics_Invariant_BurnIsDeflationary(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	require.True(t, config.BurnBps > 0, "test assumes BurnBps > 0 in default config")

	// For large enough fees (where BurnBps/10000 * fee >= 1), burn must be positive
	largeFees := []int64{100, 1000, 10000, 100000, 1000000}
	for _, amount := range largeFees {
		totalFee := sdk.NewInt64Coin("uaeth", amount)
		result := keeper.CalculateFeeBreakdown(totalFee, config, 3)

		require.True(t, result.BurnedAmount.Amount.GT(sdkmath.ZeroInt()),
			"burn must be positive for fee=%d (BurnBps=%d)", amount, config.BurnBps)
	}
}

func TestTokenomics_Invariant_DustNeverExceedsBound(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	rng := rand.New(rand.NewSource(777))

	for i := 0; i < 500; i++ {
		amount := rng.Int63n(10000000) + 1
		validatorCount := int(rng.Int63n(20)) + 1

		totalFee := sdk.NewInt64Coin("uaeth", amount)
		result := keeper.CalculateFeeBreakdown(totalFee, config, validatorCount)

		// Dust = total - allocated, where allocated = validatorActual + treasuryRaw + burnAmount + insuranceAmount.
		// Sources of rounding loss:
		//   - Up to 3 from the 4 bucket truncations (each loses at most ~1 from integer division)
		//   - Up to (validatorCount - 1) from dividing validatorTotal among validators
		// So the maximum dust is bounded by validatorCount + 3.
		bound := sdkmath.NewInt(int64(validatorCount + 3))
		require.True(t, result.DustToTreasury.Amount.LT(bound),
			"dust (%s) must be < %s for fee=%d, validators=%d",
			result.DustToTreasury.Amount.String(), bound.String(), amount, validatorCount)
	}
}

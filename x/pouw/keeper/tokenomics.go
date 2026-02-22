package keeper

import (
	"fmt"
	"math"
	"math/big"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// AETHEL TOKENOMICS — Design Principles & Parameter Model
// ---------------------------------------------------------------------------
//
// This file implements the complete tokenomics model for the AETHEL token,
// the native currency of the Aethelred sovereign L1. The model is designed
// around these principles:
//
//   1. Clear utility: staking, verification fees, slashing collateral,
//      governance voting
//   2. Sustainable issuance: avoid runaway inflation; emissions align with
//      security budget
//   3. Fee market design: predictable but responsive to demand
//   4. Incentive alignment: validators rewarded for correct verification;
//      penalized for slashable behavior
//   5. Treasury & grants: transparent rules for ecosystem funding
//   6. Vesting & distribution: long-term alignment for team and early
//      stakeholders
//   7. Explicit anti-abuse: MEV and manipulation policies
//
// All arithmetic uses integer math (sdkmath.Int). Percentages are expressed
// in basis points (10000 BPS = 100%). Time is expressed in blocks at 6s.
//
// Calendar alignment: Phase 2 (May–Jul 2026)
//   - Week 13: Emission + fee simulations
//   - Week 14: Parameter sweep and stress tests
//   - Week 15: Validator rewards + slashing rules
//   - Week 16: Governance parameter rules
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section 1: Token Supply & Emission Model
// ---------------------------------------------------------------------------

// InitialSupplyUAETH is the genesis total supply in micro-AETH.
// 1 AETH = 1,000,000 uaeth. Genesis supply = 1,000,000,000 AETH.
const InitialSupplyUAETH int64 = 1_000_000_000_000_000 // 1B AETH

// BlocksPerYear approximates the number of blocks in a year at 6s block time.
const BlocksPerYear int64 = 5_256_000

// BlocksPerDay is the number of blocks in a day at 6s block time.
const BlocksPerDay int64 = 14_400

// BlocksPerWeek is the number of blocks in a week at 6s block time.
const BlocksPerWeek int64 = 100_800

// EmissionDecayModel describes how token emission decreases over time.
type EmissionDecayModel string

const (
	EmissionLinearDecay      EmissionDecayModel = "linear"      // Linear reduction per year
	EmissionExponentialDecay EmissionDecayModel = "exponential" // Halving-style decay
	EmissionStepDecay        EmissionDecayModel = "step"        // Discrete steps at milestones
)

// EmissionConfig defines the token issuance parameters.
type EmissionConfig struct {
	// Initial annual inflation rate in BPS (e.g., 800 = 8%)
	InitialInflationBps int64

	// Long-term target inflation in BPS (e.g., 200 = 2%)
	TargetInflationBps int64

	// Decay model determines how inflation decreases over time
	DecayModel EmissionDecayModel

	// DecayPeriodYears is the number of years over which inflation
	// decays from initial to target (linear) or halves (exponential).
	DecayPeriodYears int64

	// MaxSupplyCap is the hard ceiling on total supply (0 = no cap).
	MaxSupplyCap int64

	// StakingTargetBps is the target staking participation rate in BPS
	// (e.g., 5500 = 55%). Emission is adjusted to incentivize this rate.
	StakingTargetBps int64

	// SecurityBudgetFloorBps is the minimum annual emission allocated
	// to validator security even when staking exceeds target.
	SecurityBudgetFloorBps int64
}

// DefaultEmissionConfig returns conservative emission parameters.
func DefaultEmissionConfig() EmissionConfig {
	return EmissionConfig{
		InitialInflationBps:    800, // 8% initial
		TargetInflationBps:     200, // 2% long-term target
		DecayModel:             EmissionExponentialDecay,
		DecayPeriodYears:       6,    // halving every 6 years
		MaxSupplyCap:           0,    // no hard cap, inflation-bounded
		StakingTargetBps:       5500, // 55% target staking
		SecurityBudgetFloorBps: 100,  // 1% minimum security budget
	}
}

// ValidateEmissionConfig checks that emission parameters are well-formed.
func ValidateEmissionConfig(config EmissionConfig) error {
	if config.InitialInflationBps < 100 || config.InitialInflationBps > 2000 {
		return fmt.Errorf("initial inflation must be in [100, 2000] BPS, got %d", config.InitialInflationBps)
	}
	if config.TargetInflationBps < 50 || config.TargetInflationBps > config.InitialInflationBps {
		return fmt.Errorf("target inflation must be in [50, initial=%d] BPS, got %d",
			config.InitialInflationBps, config.TargetInflationBps)
	}
	switch config.DecayModel {
	case EmissionLinearDecay, EmissionExponentialDecay, EmissionStepDecay:
		// valid
	default:
		return fmt.Errorf("unknown decay model %q", config.DecayModel)
	}
	if config.DecayPeriodYears < 2 || config.DecayPeriodYears > 20 {
		return fmt.Errorf("decay period must be in [2, 20] years, got %d", config.DecayPeriodYears)
	}
	if config.StakingTargetBps < 2000 || config.StakingTargetBps > 9000 {
		return fmt.Errorf("staking target must be in [2000, 9000] BPS, got %d", config.StakingTargetBps)
	}
	if config.SecurityBudgetFloorBps < 0 || config.SecurityBudgetFloorBps > config.InitialInflationBps {
		return fmt.Errorf("security budget floor must be in [0, initial=%d] BPS, got %d",
			config.InitialInflationBps, config.SecurityBudgetFloorBps)
	}
	return nil
}

// EmissionScheduleEntry describes the emission for a single year.
type EmissionScheduleEntry struct {
	Year             int
	InflationBps     int64
	InflationPercent float64
	AnnualEmission   int64 // uaeth minted
	CumulativeSupply int64
	StakingYield     float64 // approximate yield assuming target participation
}

// ComputeEmissionSchedule generates a multi-year emission schedule.
func ComputeEmissionSchedule(config EmissionConfig, years int) []EmissionScheduleEntry {
	schedule := make([]EmissionScheduleEntry, 0, years)
	safeMath := NewSafeMath()
	supply := sdkmath.NewInt(InitialSupplyUAETH)

	for year := 1; year <= years; year++ {
		inflationBps := computeInflationForYear(config, year)

		// Annual emission = supply * inflationBps / 10000 (SafeMath)
		emission, err := safeMath.SafeBpsMultiply(supply, inflationBps)
		if err != nil {
			break
		}
		supply, err = safeMath.SafeAdd(supply, emission)
		if err != nil {
			break
		}

		// Cap supply if max is set
		if config.MaxSupplyCap > 0 {
			maxCap := sdkmath.NewInt(config.MaxSupplyCap)
			if supply.GT(maxCap) {
				emission = emission.Sub(supply.Sub(maxCap))
				supply = maxCap
			}
		}

		// Approximate staking yield: (emission * validator_share) / (supply * staking_rate)
		validatorShare, err := safeMath.SafeBpsMultiply(emission, MainnetFeeDistribution().ValidatorRewardBps)
		if err != nil {
			break
		}
		stakingAmount, err := safeMath.SafeBpsMultiply(supply, config.StakingTargetBps)
		if err != nil {
			break
		}
		yield := ratioToPercent(validatorShare, stakingAmount)

		annualEmission, ok := mathIntToInt64(emission)
		if !ok {
			break
		}
		cumulativeSupply, ok := mathIntToInt64(supply)
		if !ok {
			break
		}

		schedule = append(schedule, EmissionScheduleEntry{
			Year:             year,
			InflationBps:     inflationBps,
			InflationPercent: float64(inflationBps) / 100,
			AnnualEmission:   annualEmission,
			CumulativeSupply: cumulativeSupply,
			StakingYield:     yield,
		})
	}

	return schedule
}

func mathIntToInt64(value sdkmath.Int) (int64, bool) {
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

func ratioToPercent(numerator, denominator sdkmath.Int) float64 {
	if denominator.IsZero() {
		return 0
	}

	ratio := new(big.Rat).SetFrac(numerator.BigInt(), denominator.BigInt())
	asFloat, _ := ratio.Float64()
	return asFloat * 100
}

// computeInflationForYear returns the inflation rate in BPS for a given year.
func computeInflationForYear(config EmissionConfig, year int) int64 {
	switch config.DecayModel {
	case EmissionLinearDecay:
		// Linear decay from initial to target over DecayPeriodYears
		if int64(year) >= config.DecayPeriodYears {
			return config.TargetInflationBps
		}
		reduction := (config.InitialInflationBps - config.TargetInflationBps) * int64(year) / config.DecayPeriodYears
		return config.InitialInflationBps - reduction

	case EmissionExponentialDecay:
		// Halving-style: initial * 0.5^(year/period)
		exponent := float64(year) / float64(config.DecayPeriodYears)
		factor := math.Pow(0.5, exponent)
		result := int64(float64(config.InitialInflationBps) * factor)
		if result < config.TargetInflationBps {
			return config.TargetInflationBps
		}
		return result

	case EmissionStepDecay:
		// Step every DecayPeriodYears/3 years
		stepSize := config.DecayPeriodYears / 3
		if stepSize < 1 {
			stepSize = 1
		}
		steps := int64(year) / stepSize
		reduction := steps * (config.InitialInflationBps - config.TargetInflationBps) / 4
		result := config.InitialInflationBps - reduction
		if result < config.TargetInflationBps {
			return config.TargetInflationBps
		}
		return result

	default:
		return config.TargetInflationBps
	}
}

// ---------------------------------------------------------------------------
// Section 2: Staking & Validator Economics
// ---------------------------------------------------------------------------

// StakingConfig defines the parameters for the staking economy.
type StakingConfig struct {
	// MinStakeUAETH is the minimum stake for a validator.
	MinStakeUAETH int64

	// MaxCommissionBps is the maximum validator commission in BPS.
	MaxCommissionBps int64

	// MinCommissionBps is the minimum validator commission in BPS.
	MinCommissionBps int64

	// UnbondingPeriodBlocks is the unbonding period in blocks.
	UnbondingPeriodBlocks int64

	// MaxValidators is the maximum number of active validators.
	MaxValidators int

	// RedelegationCooldownBlocks is the cooldown before re-delegation.
	RedelegationCooldownBlocks int64
}

// DefaultStakingConfig returns the default staking configuration.
func DefaultStakingConfig() StakingConfig {
	return StakingConfig{
		MinStakeUAETH:              1_000_000_000, // 1000 AETH
		MaxCommissionBps:           2000,          // 20%
		MinCommissionBps:           500,           // 5%
		UnbondingPeriodBlocks:      302_400,       // ~21 days at 6s blocks
		MaxValidators:              100,
		RedelegationCooldownBlocks: 100_800, // ~7 days
	}
}

// ValidateStakingConfig checks staking parameters.
func ValidateStakingConfig(config StakingConfig) error {
	if config.MinStakeUAETH < 1_000_000 {
		return fmt.Errorf("min stake must be >= 1 AETH (1000000 uaeth), got %d", config.MinStakeUAETH)
	}
	if config.MaxCommissionBps < config.MinCommissionBps {
		return fmt.Errorf("max commission (%d BPS) must be >= min commission (%d BPS)",
			config.MaxCommissionBps, config.MinCommissionBps)
	}
	if config.MinCommissionBps < 100 || config.MinCommissionBps > 5000 {
		return fmt.Errorf("min commission must be in [100, 5000] BPS, got %d", config.MinCommissionBps)
	}
	if config.MaxCommissionBps > 5000 {
		return fmt.Errorf("max commission must be <= 5000 BPS, got %d", config.MaxCommissionBps)
	}
	if config.UnbondingPeriodBlocks < BlocksPerWeek {
		return fmt.Errorf("unbonding period must be >= 1 week (%d blocks), got %d",
			BlocksPerWeek, config.UnbondingPeriodBlocks)
	}
	if config.MaxValidators < 5 || config.MaxValidators > 500 {
		return fmt.Errorf("max validators must be in [5, 500], got %d", config.MaxValidators)
	}
	return nil
}

// ValidatorEconomics computes the expected economics for a single validator.
type ValidatorEconomics struct {
	ValidatorAddress string
	StakeAmount      int64
	CommissionBps    int64
	ReputationScore  int64

	// Computed
	BaseRewardPerBlock int64
	ScaledReward       int64 // After reputation scaling
	CommissionEarnings int64
	DelegatorYieldBps  int64
	AnnualRevenue      int64
	SlashingExposure   int64
}

// ComputeValidatorEconomics calculates expected economics for a validator.
func ComputeValidatorEconomics(
	ctx sdk.Context,
	k Keeper,
	validatorAddr string,
	stakeAmount int64,
	commissionBps int64,
) (*ValidatorEconomics, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get params: %w", err)
	}

	// Get validator reputation
	stats, err := k.ValidatorStats.Get(ctx, validatorAddr)
	reputation := int64(50) // default
	if err == nil {
		reputation = stats.ReputationScore
	}

	// Base reward per job
	rewardCoin, parseErr := sdk.ParseCoinNormalized(params.VerificationReward)
	baseReward := int64(0)
	if parseErr == nil {
		baseReward = rewardCoin.Amount.Int64()
	}

	// Scale by reputation
	scaledCoin := RewardScaleByReputation(sdk.NewInt64Coin(MainnetDenom, baseReward), reputation)
	scaledReward := scaledCoin.Amount.Int64()

	// Annual projection (assumes MaxJobsPerBlock jobs per block)
	jobsPerYear := params.MaxJobsPerBlock * BlocksPerYear
	annualGrossReward := scaledReward * jobsPerYear

	// Commission earnings from delegators
	commissionEarnings := annualGrossReward * commissionBps / BpsBase

	// Slashing exposure
	penaltyCoin, penaltyErr := sdk.ParseCoinNormalized(params.SlashingPenalty)
	slashingExposure := int64(0)
	if penaltyErr != nil {
		// Log warning but don't fail - use zero exposure as default
		// This is a non-critical calculation path
		slashingExposure = 0
	} else if penaltyCoin.Amount.IsPositive() {
		slashingExposure = penaltyCoin.Amount.Int64()
	}

	// Delegator yield = (annual_reward - commission) / stake
	delegatorReward := annualGrossReward - commissionEarnings
	delegatorYield := int64(0)
	if stakeAmount > 0 {
		delegatorYield = delegatorReward * BpsBase / stakeAmount
	}

	return &ValidatorEconomics{
		ValidatorAddress:   validatorAddr,
		StakeAmount:        stakeAmount,
		CommissionBps:      commissionBps,
		ReputationScore:    reputation,
		BaseRewardPerBlock: baseReward,
		ScaledReward:       scaledReward,
		CommissionEarnings: commissionEarnings,
		DelegatorYieldBps:  delegatorYield,
		AnnualRevenue:      annualGrossReward,
		SlashingExposure:   slashingExposure,
	}, nil
}

// ---------------------------------------------------------------------------
// Section 3: Dynamic Fee Model
// ---------------------------------------------------------------------------

// FeeMarketConfig defines the dynamic fee adjustment parameters.
type FeeMarketConfig struct {
	// BaseFeeUAETH is the minimum fee per job in uaeth.
	BaseFeeUAETH int64

	// MaxMultiplierBps is the maximum congestion multiplier in BPS
	// (e.g., 50000 = 5.0x).
	MaxMultiplierBps int64

	// CongestionThresholdBps is the job queue utilization at which
	// dynamic pricing starts (in BPS of MaxJobsPerBlock).
	CongestionThresholdBps int64

	// FeeAdjustmentRateBps is how fast fees adjust per block when
	// congestion exceeds threshold.
	FeeAdjustmentRateBps int64

	// PriorityFeeTiers defines multipliers for priority levels.
	PriorityFeeTiers []PriorityFeeTier
}

// PriorityFeeTier maps a priority level to a fee multiplier.
type PriorityFeeTier struct {
	Name          string
	MultiplierBps int64 // e.g., 10000 = 1.0x, 20000 = 2.0x
}

// DefaultFeeMarketConfig returns the default fee market configuration.
func DefaultFeeMarketConfig() FeeMarketConfig {
	return FeeMarketConfig{
		BaseFeeUAETH:           1000,  // 0.001 AETH
		MaxMultiplierBps:       50000, // 5.0x max
		CongestionThresholdBps: 7000,  // 70% utilization triggers dynamic pricing
		FeeAdjustmentRateBps:   100,   // 1% per block adjustment
		PriorityFeeTiers: []PriorityFeeTier{
			{Name: "standard", MultiplierBps: 10000}, // 1.0x
			{Name: "fast", MultiplierBps: 20000},     // 2.0x
			{Name: "urgent", MultiplierBps: 50000},   // 5.0x
		},
	}
}

// ValidateFeeMarketConfig checks fee market parameters.
func ValidateFeeMarketConfig(config FeeMarketConfig) error {
	if config.BaseFeeUAETH <= 0 {
		return fmt.Errorf("base fee must be positive, got %d", config.BaseFeeUAETH)
	}
	if config.MaxMultiplierBps < 10000 || config.MaxMultiplierBps > 100000 {
		return fmt.Errorf("max multiplier must be in [10000, 100000] BPS, got %d", config.MaxMultiplierBps)
	}
	if config.CongestionThresholdBps < 3000 || config.CongestionThresholdBps > 9500 {
		return fmt.Errorf("congestion threshold must be in [3000, 9500] BPS, got %d", config.CongestionThresholdBps)
	}
	if len(config.PriorityFeeTiers) == 0 {
		return fmt.Errorf("at least one priority fee tier required")
	}
	for _, tier := range config.PriorityFeeTiers {
		if tier.MultiplierBps < 10000 {
			return fmt.Errorf("priority tier %q multiplier must be >= 10000 BPS, got %d",
				tier.Name, tier.MultiplierBps)
		}
	}
	return nil
}

// ComputeDynamicFee calculates the current job fee based on congestion.
func ComputeDynamicFee(config FeeMarketConfig, pendingJobs int, maxJobsPerBlock int64) int64 {
	if maxJobsPerBlock <= 0 {
		return config.BaseFeeUAETH
	}

	// Utilization = pendingJobs / (maxJobsPerBlock * backlog_window)
	backlogWindow := int64(10) // 10 blocks of backlog capacity
	capacity := maxJobsPerBlock * backlogWindow
	utilizationBps := int64(0)
	if capacity > 0 {
		utilizationBps = int64(pendingJobs) * BpsBase / capacity
	}

	// If below threshold, use base fee
	if utilizationBps <= config.CongestionThresholdBps {
		return config.BaseFeeUAETH
	}

	// Linear interpolation from 1x to MaxMultiplier
	excessBps := utilizationBps - config.CongestionThresholdBps
	rangeBps := BpsBase - config.CongestionThresholdBps
	if rangeBps <= 0 {
		rangeBps = 1
	}

	multiplierBps := int64(10000) + (config.MaxMultiplierBps-10000)*excessBps/rangeBps
	if multiplierBps > config.MaxMultiplierBps {
		multiplierBps = config.MaxMultiplierBps
	}

	return config.BaseFeeUAETH * multiplierBps / BpsBase
}

// ---------------------------------------------------------------------------
// Section 4: Slashing & Security Economics
// ---------------------------------------------------------------------------

// SlashingTier defines a slashing severity level.
type SlashingTier struct {
	Name           string
	SlashBps       int64 // % of stake slashed
	JailBlocks     int64 // blocks jailed
	EvidenceMaxAge int64 // max age of evidence in blocks
	Description    string
	IsPermaban     bool // permanent ban if true
}

// SlashingConfig defines the complete slashing parameter set.
type SlashingConfig struct {
	Tiers []SlashingTier

	// DoubleSignSlashBps is the penalty for double-signing.
	DoubleSignSlashBps int64

	// DowntimeSlashBps is the penalty for extended downtime.
	DowntimeSlashBps int64

	// DowntimeWindowBlocks is the window for downtime detection.
	DowntimeWindowBlocks int64

	// MinSignedPerWindow is the minimum signed blocks in BPS.
	MinSignedPerWindowBps int64

	// InsurancePoolMinBps is the minimum insurance pool as % of total staked.
	InsurancePoolMinBps int64
}

// DefaultSlashingConfig returns the default slashing parameters.
func DefaultSlashingConfig() SlashingConfig {
	return SlashingConfig{
		Tiers: []SlashingTier{
			{
				Name:           "minor_fault",
				SlashBps:       50,    // 0.5%
				JailBlocks:     14400, // ~1 day
				EvidenceMaxAge: BlocksPerWeek,
				Description:    "Minor operational failures (brief downtime, late votes)",
			},
			{
				Name:           "major_fault",
				SlashBps:       1000, // 10%
				JailBlocks:     BlocksPerWeek,
				EvidenceMaxAge: BlocksPerWeek * 4,
				Description:    "Major failures (incorrect verification, repeated downtime)",
			},
			{
				Name:           "fraud",
				SlashBps:       5000, // 50%
				JailBlocks:     BlocksPerYear,
				EvidenceMaxAge: BlocksPerYear,
				Description:    "Fraudulent behavior (fake attestations, proof manipulation)",
				IsPermaban:     true,
			},
			{
				Name:           "critical_byzantine",
				SlashBps:       10000, // 100% — full slash
				JailBlocks:     0,     // permanent
				EvidenceMaxAge: BlocksPerYear,
				Description:    "Critical byzantine attack (double-signing, chain halt attempt)",
				IsPermaban:     true,
			},
		},
		DoubleSignSlashBps:    5000,  // 50%
		DowntimeSlashBps:      100,   // 1%
		DowntimeWindowBlocks:  10000, // ~16.6 hours
		MinSignedPerWindowBps: 5000,  // 50% of window
		InsurancePoolMinBps:   500,   // 5% of total staked
	}
}

// ValidateSlashingConfig checks slashing parameters.
func ValidateSlashingConfig(config SlashingConfig) error {
	if len(config.Tiers) == 0 {
		return fmt.Errorf("at least one slashing tier required")
	}
	for _, tier := range config.Tiers {
		if tier.SlashBps < 0 || tier.SlashBps > 10000 {
			return fmt.Errorf("tier %q slash BPS must be in [0, 10000], got %d", tier.Name, tier.SlashBps)
		}
		if tier.Name == "" {
			return fmt.Errorf("tier name must not be empty")
		}
	}
	if config.DoubleSignSlashBps < 1000 || config.DoubleSignSlashBps > 10000 {
		return fmt.Errorf("double-sign slash must be in [1000, 10000] BPS, got %d", config.DoubleSignSlashBps)
	}
	if config.DowntimeSlashBps < 10 || config.DowntimeSlashBps > 1000 {
		return fmt.Errorf("downtime slash must be in [10, 1000] BPS, got %d", config.DowntimeSlashBps)
	}
	if config.MinSignedPerWindowBps < 2000 || config.MinSignedPerWindowBps > 9000 {
		return fmt.Errorf("min signed per window must be in [2000, 9000] BPS, got %d",
			config.MinSignedPerWindowBps)
	}
	return nil
}

// ComputeSlashAmount calculates the slash for a given tier and stake.
func ComputeSlashAmount(tier SlashingTier, stakedUAETH int64) int64 {
	return stakedUAETH * tier.SlashBps / BpsBase
}

// DeterrenceRatio computes the ratio of slash penalty to potential gain.
// A ratio > 1 means slashing is a deterrent (penalty exceeds potential gain).
func DeterrenceRatio(slashAmount int64, potentialGain int64) float64 {
	if potentialGain <= 0 {
		return math.Inf(1) // infinite deterrence
	}
	return float64(slashAmount) / float64(potentialGain)
}

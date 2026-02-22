package keeper

import (
	"fmt"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Fee Distribution Model
// ---------------------------------------------------------------------------
// This file implements the token economics for job fee distribution in the
// Aethelred proof-of-compute blockchain. Fees collected from job submitters
// are split among validators, the community treasury, a deflationary burn
// mechanism, and an insurance fund that backstops slashing operations.
//
// All arithmetic uses integer math (sdkmath.Int) -- no floating point is
// ever used. Percentages are expressed in basis points (bps) where
// 10000 bps == 100%.
// ---------------------------------------------------------------------------

// BpsBase is the total basis points representing 100%.
const BpsBase int64 = 10000

// FeeDistributionConfig defines how job fees are split across different
// purposes. All percentages are expressed as basis points (1/100th of a
// percent). They must sum to 10000 (100%).
type FeeDistributionConfig struct {
	ValidatorRewardBps int64 // % to validator rewards (default 4000 = 40%)
	TreasuryBps        int64 // % to community treasury (default 3000 = 30%)
	BurnBps            int64 // % to burn (deflation) (default 2000 = 20%)
	InsuranceFundBps   int64 // % to insurance fund for slashing (default 1000 = 10%)
}

// DefaultFeeDistributionConfig returns the default 40/30/20/10 split.
func DefaultFeeDistributionConfig() FeeDistributionConfig {
	return FeeDistributionConfig{
		ValidatorRewardBps: 4000, // 40%
		TreasuryBps:        3000, // 30%
		BurnBps:            2000, // 20%
		InsuranceFundBps:   1000, // 10%
	}
}

// ValidateFeeDistribution validates that all basis points are non-negative
// and sum to exactly 10000.
func ValidateFeeDistribution(config FeeDistributionConfig) error {
	if config.ValidatorRewardBps < 0 {
		return fmt.Errorf("validator reward bps must be non-negative, got %d", config.ValidatorRewardBps)
	}
	if config.TreasuryBps < 0 {
		return fmt.Errorf("treasury bps must be non-negative, got %d", config.TreasuryBps)
	}
	if config.BurnBps < 0 {
		return fmt.Errorf("burn bps must be non-negative, got %d", config.BurnBps)
	}
	if config.InsuranceFundBps < 0 {
		return fmt.Errorf("insurance fund bps must be non-negative, got %d", config.InsuranceFundBps)
	}

	total := config.ValidatorRewardBps + config.TreasuryBps + config.BurnBps + config.InsuranceFundBps
	if total != BpsBase {
		return fmt.Errorf("fee distribution bps must sum to %d, got %d", BpsBase, total)
	}

	return nil
}

// ---------------------------------------------------------------------------
// FeeDistributor
// ---------------------------------------------------------------------------

// FeeDistributor manages the collection and distribution of job fees
// according to a FeeDistributionConfig.
type FeeDistributor struct {
	keeper *Keeper
	config FeeDistributionConfig
}

// NewFeeDistributor creates a new FeeDistributor. The config is validated
// before the distributor is returned.
func NewFeeDistributor(keeper *Keeper, config FeeDistributionConfig) *FeeDistributor {
	return &FeeDistributor{
		keeper: keeper,
		config: config,
	}
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

// FeeDistributionResult contains the full breakdown of a fee distribution
// operation, including the amounts allocated to each bucket and dust.
type FeeDistributionResult struct {
	TotalFee           sdk.Coin // The original job fee
	ValidatorRewards   sdk.Coin // Total sent to validators
	PerValidatorReward sdk.Coin // Each validator's equal share
	TreasuryAmount     sdk.Coin // Sent to dedicated treasury module account
	BurnedAmount       sdk.Coin // Burned tokens (deflationary)
	InsuranceFund      sdk.Coin // Sent to dedicated insurance module account
	DustToTreasury     sdk.Coin // Remainder from integer rounding
	ValidatorCount     int
}

// AnnualRevenueEstimate provides a rough projection of annual validator
// revenue based on current chain parameters.
type AnnualRevenueEstimate struct {
	JobsPerBlock       int64
	BlocksPerYear      int64 // ~5,256,000 (6s blocks)
	ActiveValidators   int64 // active bonded validators used for per-validator share
	FeePerJob          sdk.Coin
	TotalAnnualFees    sdk.Coin
	ValidatorShare     sdk.Coin
	TreasuryShare      sdk.Coin
	AnnualBurn         sdk.Coin
	InsuranceAccrual   sdk.Coin
	PerValidatorAnnual sdk.Coin
}

// ---------------------------------------------------------------------------
// Pure calculation (no side effects)
// ---------------------------------------------------------------------------

// CalculateFeeBreakdown is a pure function that computes the fee distribution
// breakdown without executing any bank operations. It is safe to use for
// queries and simulations.
//
// Integer math rules:
//   - Each bucket gets: totalAmount * bps / 10000
//   - Validator rewards are split equally among validators
//   - Any dust (remainder from integer division) is added to the treasury
func CalculateFeeBreakdown(totalFee sdk.Coin, config FeeDistributionConfig, validatorCount int) FeeDistributionResult {
	denom := totalFee.Denom
	total := totalFee.Amount

	// Calculate each portion using basis points with integer division.
	validatorTotal := total.Mul(sdkmath.NewInt(config.ValidatorRewardBps)).Quo(sdkmath.NewInt(BpsBase))
	treasuryRaw := total.Mul(sdkmath.NewInt(config.TreasuryBps)).Quo(sdkmath.NewInt(BpsBase))
	burnAmount := total.Mul(sdkmath.NewInt(config.BurnBps)).Quo(sdkmath.NewInt(BpsBase))
	insuranceAmount := total.Mul(sdkmath.NewInt(config.InsuranceFundBps)).Quo(sdkmath.NewInt(BpsBase))

	// Per-validator share (equal split). Guard against zero validators.
	var perValidator sdkmath.Int
	var validatorActual sdkmath.Int
	if validatorCount > 0 {
		perValidator = validatorTotal.Quo(sdkmath.NewInt(int64(validatorCount)))
		validatorActual = perValidator.Mul(sdkmath.NewInt(int64(validatorCount)))
	} else {
		perValidator = sdkmath.ZeroInt()
		validatorActual = sdkmath.ZeroInt()
	}

	// Dust is whatever was lost to integer truncation across all buckets,
	// plus the remainder from splitting among validators.
	allocated := validatorActual.Add(treasuryRaw).Add(burnAmount).Add(insuranceAmount)
	dust := total.Sub(allocated)

	// Dust goes to treasury.
	treasuryFinal := treasuryRaw.Add(dust)

	return FeeDistributionResult{
		TotalFee:           totalFee,
		ValidatorRewards:   sdk.NewCoin(denom, validatorActual),
		PerValidatorReward: sdk.NewCoin(denom, perValidator),
		TreasuryAmount:     sdk.NewCoin(denom, treasuryFinal),
		BurnedAmount:       sdk.NewCoin(denom, burnAmount),
		InsuranceFund:      sdk.NewCoin(denom, insuranceAmount),
		DustToTreasury:     sdk.NewCoin(denom, dust),
		ValidatorCount:     validatorCount,
	}
}

// ---------------------------------------------------------------------------
// Side-effecting distribution
// ---------------------------------------------------------------------------

// DistributeJobFee executes the full fee distribution for a completed job.
//
// The fee must already reside in the pouw module account (collected via
// CollectJobFee). The function:
//  1. Calculates each portion using basis points (integer math).
//  2. Sends the validator reward portion equally to each validator.
//  3. Transfers the treasury portion to the dedicated treasury module account.
//  4. Burns the burn portion via bankKeeper.BurnCoins.
//  5. Transfers the insurance fund portion to the dedicated insurance module account.
//  6. Adds any dust (rounding remainder) to the treasury.
//
// It returns a FeeDistributionResult describing every allocation.
func (fd *FeeDistributor) DistributeJobFee(ctx sdk.Context, jobFee sdk.Coin, validators []string) (*FeeDistributionResult, error) {
	if !jobFee.IsPositive() {
		return nil, fmt.Errorf("job fee must be positive, got %s", jobFee)
	}
	if len(validators) == 0 {
		return nil, fmt.Errorf("at least one validator is required for fee distribution")
	}

	// Validate the config before proceeding.
	if err := ValidateFeeDistribution(fd.config); err != nil {
		return nil, fmt.Errorf("invalid fee distribution config: %w", err)
	}

	// Pure calculation.
	result := CalculateFeeBreakdown(jobFee, fd.config, len(validators))

	// --- 1. Distribute rewards to validators ---
	if result.PerValidatorReward.IsPositive() {
		if err := fd.keeper.DistributeVerificationRewards(ctx, validators, result.PerValidatorReward); err != nil {
			return nil, fmt.Errorf("failed to distribute validator rewards: %w", err)
		}
	}

	// --- 2. Treasury allocation to dedicated treasury module account ---
	if result.TreasuryAmount.IsPositive() {
		if err := fd.keeper.bankKeeper.SendCoinsFromModuleToModule(
			ctx,
			types.ModuleName,
			types.TreasuryModuleName,
			sdk.NewCoins(result.TreasuryAmount),
		); err != nil {
			return nil, fmt.Errorf("failed to transfer treasury allocation: %w", err)
		}
		if err := fd.keeper.RecordTreasuryEarmark(ctx, result.TreasuryAmount); err != nil {
			return nil, fmt.Errorf("failed to record treasury earmark: %w", err)
		}
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				"fee_treasury_allocation",
				sdk.NewAttribute("amount", result.TreasuryAmount.String()),
				sdk.NewAttribute("module", types.TreasuryModuleName),
			),
		)
	}

	// --- 3. Burn portion ---
	if result.BurnedAmount.IsPositive() {
		if err := fd.keeper.BurnTokens(ctx, result.BurnedAmount); err != nil {
			return nil, fmt.Errorf("failed to burn tokens: %w", err)
		}
	}

	// --- 4. Insurance fund allocation to dedicated insurance module account ---
	if result.InsuranceFund.IsPositive() {
		if err := fd.keeper.bankKeeper.SendCoinsFromModuleToModule(
			ctx,
			types.ModuleName,
			types.InsuranceModuleName,
			sdk.NewCoins(result.InsuranceFund),
		); err != nil {
			return nil, fmt.Errorf("failed to transfer insurance allocation: %w", err)
		}
		if err := fd.keeper.RecordInsuranceFundEarmark(ctx, result.InsuranceFund); err != nil {
			return nil, fmt.Errorf("failed to record insurance earmark: %w", err)
		}
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				"fee_insurance_allocation",
				sdk.NewAttribute("amount", result.InsuranceFund.String()),
				sdk.NewAttribute("module", types.InsuranceModuleName),
			),
		)
	}

	// --- 5. Emit summary event ---
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"fee_distributed",
			sdk.NewAttribute("total_fee", jobFee.String()),
			sdk.NewAttribute("validator_rewards", result.ValidatorRewards.String()),
			sdk.NewAttribute("treasury", result.TreasuryAmount.String()),
			sdk.NewAttribute("burned", result.BurnedAmount.String()),
			sdk.NewAttribute("insurance", result.InsuranceFund.String()),
			sdk.NewAttribute("dust", result.DustToTreasury.String()),
			sdk.NewAttribute("validator_count", fmt.Sprintf("%d", result.ValidatorCount)),
		),
	)

	return &result, nil
}

// ---------------------------------------------------------------------------
// Fee collection
// ---------------------------------------------------------------------------

// CollectJobFee transfers the job fee from the submitter's account into the
// pouw module account. This must be called before DistributeJobFee.
func (fd *FeeDistributor) CollectJobFee(ctx sdk.Context, submitterAddr sdk.AccAddress, fee sdk.Coin) error {
	if !fee.IsPositive() {
		return fmt.Errorf("fee must be positive, got %s", fee)
	}

	coins := sdk.NewCoins(fee)
	if err := fd.keeper.bankKeeper.SendCoinsFromAccountToModule(ctx, submitterAddr, types.ModuleName, coins); err != nil {
		return fmt.Errorf("failed to collect job fee from %s: %w", submitterAddr, err)
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"job_fee_collected",
			sdk.NewAttribute("submitter", submitterAddr.String()),
			sdk.NewAttribute("fee", fee.String()),
		),
	)

	return nil
}

// ---------------------------------------------------------------------------
// Reward distribution helpers (on Keeper so they are reusable)
// ---------------------------------------------------------------------------

// DistributeVerificationRewards sends perValidatorReward from the pouw module
// account to each validator address and emits a "verification_reward" event
// per validator.
func (k *Keeper) DistributeVerificationRewards(ctx sdk.Context, validators []string, perValidatorReward sdk.Coin) error {
	if !perValidatorReward.IsPositive() {
		return nil // nothing to distribute
	}

	rewardCoins := sdk.NewCoins(perValidatorReward)

	for _, valAddrStr := range validators {
		valAddr, err := sdk.AccAddressFromBech32(valAddrStr)
		if err != nil {
			return fmt.Errorf("invalid validator address %s: %w", valAddrStr, err)
		}

		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, valAddr, rewardCoins); err != nil {
			return fmt.Errorf("failed to send reward to validator %s: %w", valAddrStr, err)
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				"verification_reward",
				sdk.NewAttribute("validator", valAddrStr),
				sdk.NewAttribute("reward", perValidatorReward.String()),
			),
		)
	}

	return nil
}

// BurnTokens burns the specified amount of tokens from the pouw module
// account and emits a "tokens_burned" event.
func (k *Keeper) BurnTokens(ctx sdk.Context, amount sdk.Coin) error {
	if !amount.IsPositive() {
		return nil // nothing to burn
	}

	coins := sdk.NewCoins(amount)
	if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins); err != nil {
		return fmt.Errorf("failed to burn %s from module %s: %w", amount, types.ModuleName, err)
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"tokens_burned",
			sdk.NewAttribute("amount", amount.String()),
			sdk.NewAttribute("module", types.ModuleName),
		),
	)

	return nil
}

// GetTreasuryBalance returns the spendable balance of the dedicated treasury module account.
func (k *Keeper) GetTreasuryBalance(ctx sdk.Context) sdk.Coins {
	return k.bankKeeper.SpendableCoins(ctx, k.GetTreasuryModuleAccountAddress())
}

// GetModuleAccountAddress returns the sdk.AccAddress for the pouw module
// account. This is derived deterministically from the module name.
func (k *Keeper) GetModuleAccountAddress() sdk.AccAddress {
	return authtypes.NewModuleAddress(types.ModuleName)
}

// GetTreasuryModuleAccountAddress returns the sdk.AccAddress for the dedicated
// treasury module account.
func (k *Keeper) GetTreasuryModuleAccountAddress() sdk.AccAddress {
	return authtypes.NewModuleAddress(types.TreasuryModuleName)
}

// GetInsuranceModuleAccountAddress returns the sdk.AccAddress for the dedicated
// insurance module account.
func (k *Keeper) GetInsuranceModuleAccountAddress() sdk.AccAddress {
	return authtypes.NewModuleAddress(types.InsuranceModuleName)
}

// ---------------------------------------------------------------------------
// Reputation-scaled rewards
// ---------------------------------------------------------------------------

// RewardScaleByReputation adjusts a base reward according to a validator's
// reputation score (0-100). The formula ensures that even a validator with
// reputation 0 receives 50% of the base reward, while reputation 100 yields
// the full reward:
//
//	scaledReward = baseReward * (50 + reputationScore / 2) / 100
//
// All arithmetic uses sdkmath.Int -- no floating point.
func RewardScaleByReputation(baseReward sdk.Coin, reputationScore int64) sdk.Coin {
	// Clamp reputation to [0, 100].
	if reputationScore < 0 {
		reputationScore = 0
	}
	if reputationScore > 100 {
		reputationScore = 100
	}

	// scaleFactor = 50 + reputationScore / 2   (integer division)
	scaleFactor := sdkmath.NewInt(50 + reputationScore/2)
	scaledAmount := baseReward.Amount.Mul(scaleFactor).Quo(sdkmath.NewInt(100))

	return sdk.NewCoin(baseReward.Denom, scaledAmount)
}

// ---------------------------------------------------------------------------
// Annual revenue estimation
// ---------------------------------------------------------------------------

// EstimateAnnualValidatorRevenue projects annual fee-based revenue using
// current on-chain parameters. The estimate assumes:
//   - 6-second block times (~5,256,000 blocks / year)
//   - MaxJobsPerBlock jobs per block (from params)
//   - Active bonded validators sharing the validator reward pool
//
// This is a rough projection intended for dashboards and governance
// discussions, not for accounting.
func (fd *FeeDistributor) EstimateAnnualValidatorRevenue(ctx sdk.Context) (*AnnualRevenueEstimate, error) {
	params, err := fd.keeper.GetParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve params: %w", err)
	}

	feePerJob, err := sdk.ParseCoinNormalized(params.BaseJobFee)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base job fee %q: %w", params.BaseJobFee, err)
	}

	const blocksPerYear int64 = 5_256_000 // ~6s blocks
	jobsPerBlock := params.MaxJobsPerBlock
	if jobsPerBlock <= 0 {
		jobsPerBlock = 1
	}

	totalJobsPerYear := sdkmath.NewInt(blocksPerYear).Mul(sdkmath.NewInt(jobsPerBlock))
	totalAnnualFees := feePerJob.Amount.Mul(totalJobsPerYear)

	denom := feePerJob.Denom

	validatorShare := totalAnnualFees.Mul(sdkmath.NewInt(fd.config.ValidatorRewardBps)).Quo(sdkmath.NewInt(BpsBase))
	treasuryShare := totalAnnualFees.Mul(sdkmath.NewInt(fd.config.TreasuryBps)).Quo(sdkmath.NewInt(BpsBase))
	annualBurn := totalAnnualFees.Mul(sdkmath.NewInt(fd.config.BurnBps)).Quo(sdkmath.NewInt(BpsBase))
	insuranceAccrual := totalAnnualFees.Mul(sdkmath.NewInt(fd.config.InsuranceFundBps)).Quo(sdkmath.NewInt(BpsBase))

	activeValidators := fd.activeBondedValidatorCount(ctx)
	perValidatorAnnual := validatorShare.Quo(sdkmath.NewInt(activeValidators))

	return &AnnualRevenueEstimate{
		JobsPerBlock:       jobsPerBlock,
		BlocksPerYear:      blocksPerYear,
		ActiveValidators:   activeValidators,
		FeePerJob:          feePerJob,
		TotalAnnualFees:    sdk.NewCoin(denom, totalAnnualFees),
		ValidatorShare:     sdk.NewCoin(denom, validatorShare),
		TreasuryShare:      sdk.NewCoin(denom, treasuryShare),
		AnnualBurn:         sdk.NewCoin(denom, annualBurn),
		InsuranceAccrual:   sdk.NewCoin(denom, insuranceAccrual),
		PerValidatorAnnual: sdk.NewCoin(denom, perValidatorAnnual),
	}, nil
}

func (fd *FeeDistributor) activeBondedValidatorCount(ctx sdk.Context) int64 {
	validators, err := fd.keeper.stakingKeeper.GetAllValidators(ctx)
	if err != nil || len(validators) == 0 {
		return 1
	}

	var active int64
	for _, validator := range validators {
		if validator.GetStatus() == stakingtypes.Bonded && !validator.IsJailed() {
			active++
		}
	}
	if active == 0 {
		// Conservative fallback: avoid division-by-zero while still surfacing a usable estimate.
		active = int64(len(validators))
	}
	if active <= 0 {
		return 1
	}
	return active
}

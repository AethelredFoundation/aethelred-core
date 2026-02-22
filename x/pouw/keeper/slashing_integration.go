// Package keeper provides the slashing integration for Aethelred's Proof-of-Useful-Work
// consensus, connecting the evidence system to the Cosmos SDK staking/slashing modules.
//
// AS-16: Downtime Slashing Integration
// This file completes the integration between the PoUW evidence system and
// the standard Cosmos SDK slashing module.
package keeper

import (
	"context"
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// =============================================================================
// Slashing Module Adapter
// =============================================================================

// SlashingModuleAdapter adapts the Cosmos SDK slashing module for PoUW evidence.
// It provides a unified interface for applying slashing penalties from both
// traditional consensus misbehavior and PoUW-specific violations.
type SlashingModuleAdapter struct {
	logger          log.Logger
	stakingKeeper   StakingKeeperInterface
	slashingKeeper  SlashingKeeperInterface
	bankKeeper      BankKeeperInterface
	insuranceKeeper InsuranceEscrowKeeper

	// Configuration
	config SlashingAdapterConfig
}

// StakingKeeperInterface defines the staking keeper methods needed for slashing
type StakingKeeperInterface interface {
	GetValidator(ctx sdk.Context, addr sdk.ValAddress) (stakingtypes.Validator, error)
	GetValidatorByConsAddr(ctx sdk.Context, consAddr sdk.ConsAddress) (stakingtypes.Validator, error)
	Slash(ctx sdk.Context, consAddr sdk.ConsAddress, infractionHeight int64, power int64, slashFactor sdkmath.LegacyDec) (sdkmath.Int, error)
	Jail(ctx sdk.Context, consAddr sdk.ConsAddress) error
	Unjail(ctx sdk.Context, consAddr sdk.ConsAddress) error
	GetLastValidatorPower(ctx sdk.Context, operator sdk.ValAddress) (int64, error)
	GetAllValidators(ctx sdk.Context) ([]stakingtypes.Validator, error)
	Delegation(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) (stakingtypes.Delegation, error)
}

// SlashingKeeperInterface defines the slashing keeper methods needed
type SlashingKeeperInterface interface {
	GetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress) (slashingtypes.ValidatorSigningInfo, error)
	SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info slashingtypes.ValidatorSigningInfo) error
	GetParams(ctx sdk.Context) (slashingtypes.Params, error)
	JailUntil(ctx sdk.Context, consAddr sdk.ConsAddress, jailTime time.Time) error
	Tombstone(ctx sdk.Context, consAddr sdk.ConsAddress) error
	IsTombstoned(ctx sdk.Context, consAddr sdk.ConsAddress) bool
}

// BankKeeperInterface defines the bank keeper methods needed
type BankKeeperInterface interface {
	SendCoinsFromModuleToModule(ctx sdk.Context, senderModule, recipientModule string, amt sdk.Coins) error
	BurnCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error
}

// InsuranceEscrowKeeper defines the insurance escrow hook used for
// anomaly-driven appeal handling of 100% cryptographic-fault slashes.
type InsuranceEscrowKeeper interface {
	EscrowFraudSlash(
		ctx context.Context,
		validatorAddr string,
		amount sdkmath.Int,
		reason string,
		evidenceHash string,
	) (string, error)
}

// SlashingAdapterConfig contains configuration for the slashing adapter
type SlashingAdapterConfig struct {
	// PoUW-specific slashing fractions (in basis points for precision)
	DowntimeSlashBps        int64 // Default: 500 (5%)
	DoubleSignSlashBps      int64 // Default: 5000 (50%)
	InvalidOutputSlashBps   int64 // Default: 10000 (100%)
	CollusionSlashBps       int64 // Default: 10000 (100%)
	FakeAttestationSlashBps int64 // Default: 10000 (100%)

	// Jail durations
	DowntimeJailDuration        time.Duration // Default: 24 hours
	DoubleSignJailDuration      time.Duration // Default: 30 days
	InvalidOutputJailDuration   time.Duration // Default: 7 days
	CollusionJailDuration       time.Duration // Default: 365 days (permanent)
	FakeAttestationJailDuration time.Duration // Default: 365 days

	// Thresholds
	MinSlashableTokens sdkmath.Int // Minimum tokens to slash (avoid dust)

	// Feature flags
	EnableTombstoning bool // Whether to tombstone for severe violations
	EnableBurning     bool // Whether to burn slashed tokens
}

// DefaultSlashingAdapterConfig returns production-ready default configuration
func DefaultSlashingAdapterConfig() SlashingAdapterConfig {
	return SlashingAdapterConfig{
		DowntimeSlashBps:        500,   // 5%
		DoubleSignSlashBps:      5000,  // 50%
		InvalidOutputSlashBps:   10000, // 100%
		CollusionSlashBps:       10000, // 100%
		FakeAttestationSlashBps: 10000, // 100%

		DowntimeJailDuration:        24 * time.Hour,
		DoubleSignJailDuration:      30 * 24 * time.Hour,
		InvalidOutputJailDuration:   7 * 24 * time.Hour,
		CollusionJailDuration:       365 * 24 * time.Hour,
		FakeAttestationJailDuration: 365 * 24 * time.Hour,

		MinSlashableTokens: sdkmath.NewInt(1000), // 1000 uaeth minimum
		EnableTombstoning:  true,
		EnableBurning:      true,
	}
}

// emitEventIfEnabled avoids nil dereference in tests or minimal contexts that
// do not initialize an event manager.
func emitEventIfEnabled(ctx sdk.Context, event sdk.Event) {
	if em := ctx.EventManager(); em != nil {
		em.EmitEvent(event)
	}
}

// NewSlashingModuleAdapter creates a new slashing module adapter
func NewSlashingModuleAdapter(
	logger log.Logger,
	stakingKeeper StakingKeeperInterface,
	slashingKeeper SlashingKeeperInterface,
	bankKeeper BankKeeperInterface,
	config SlashingAdapterConfig,
) *SlashingModuleAdapter {
	return &SlashingModuleAdapter{
		logger:          logger,
		stakingKeeper:   stakingKeeper,
		slashingKeeper:  slashingKeeper,
		bankKeeper:      bankKeeper,
		insuranceKeeper: nil,
		config:          config,
	}
}

// SetInsuranceEscrowKeeper installs the optional insurance escrow sink.
func (a *SlashingModuleAdapter) SetInsuranceEscrowKeeper(keeper InsuranceEscrowKeeper) {
	a.insuranceKeeper = keeper
}

func (a *SlashingModuleAdapter) escrowFraudSlashIfEnabled(
	ctx sdk.Context,
	validatorAddr string,
	slashedAmount sdkmath.Int,
	reason string,
	evidenceHash string,
) {
	if a.insuranceKeeper == nil {
		return
	}
	if !slashedAmount.IsPositive() {
		return
	}

	escrowID, err := a.insuranceKeeper.EscrowFraudSlash(
		ctx,
		validatorAddr,
		slashedAmount,
		reason,
		evidenceHash,
	)
	if err != nil {
		a.logger.Error("Failed to escrow fraud slash in insurance module",
			"validator", validatorAddr,
			"reason", reason,
			"error", err,
		)
		return
	}

	a.logger.Info("Escrowed fraud slash for insurance tribunal",
		"validator", validatorAddr,
		"reason", reason,
		"escrow_id", escrowID,
		"amount", slashedAmount.String(),
	)
}

// =============================================================================
// Slashing Operations
// =============================================================================

// SlashForDowntime slashes a validator for missing blocks (liveness failure)
func (a *SlashingModuleAdapter) SlashForDowntime(
	ctx sdk.Context,
	consAddr sdk.ConsAddress,
	missedBlocks int64,
	infractionHeight int64,
) (*PoUWSlashResult, error) {
	// Check if already tombstoned
	if a.slashingKeeper != nil && a.slashingKeeper.IsTombstoned(ctx, consAddr) {
		return nil, fmt.Errorf("validator %s is tombstoned", consAddr.String())
	}

	// Get validator
	validator, err := a.stakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
	if err != nil {
		return nil, fmt.Errorf("validator not found: %w", err)
	}

	// Get voting power at infraction height.
	power := validator.GetConsensusPower(sdk.DefaultPowerReduction)
	valAddr, addrErr := sdk.ValAddressFromBech32(validator.GetOperator())
	if addrErr == nil {
		if historicalPower, powerErr := a.stakingKeeper.GetLastValidatorPower(ctx, valAddr); powerErr == nil {
			power = historicalPower
		}
	}

	// Calculate slash fraction
	slashFraction := sdkmath.LegacyNewDecWithPrec(a.config.DowntimeSlashBps, 4)

	// Execute slash
	slashedAmount, err := a.stakingKeeper.Slash(ctx, consAddr, infractionHeight, power, slashFraction)
	if err != nil {
		return nil, fmt.Errorf("slash failed: %w", err)
	}

	// Jail the validator
	jailUntil := ctx.BlockTime().Add(a.config.DowntimeJailDuration)
	if a.slashingKeeper != nil {
		if err := a.slashingKeeper.JailUntil(ctx, consAddr, jailUntil); err != nil {
			a.logger.Error("Failed to jail validator", "error", err, "validator", consAddr.String())
		}
	} else {
		if err := a.stakingKeeper.Jail(ctx, consAddr); err != nil {
			a.logger.Error("Failed to jail validator", "error", err, "validator", consAddr.String())
		}
	}

	// Update signing info
	if a.slashingKeeper != nil {
		signingInfo, err := a.slashingKeeper.GetValidatorSigningInfo(ctx, consAddr)
		if err == nil {
			signingInfo.JailedUntil = jailUntil
			signingInfo.MissedBlocksCounter = missedBlocks
			_ = a.slashingKeeper.SetValidatorSigningInfo(ctx, consAddr, signingInfo)
		}
	}

	// Emit event
	emitEventIfEnabled(ctx, sdk.NewEvent(
		"pouw_slash_downtime",
		sdk.NewAttribute("validator", consAddr.String()),
		sdk.NewAttribute("slashed_amount", slashedAmount.String()),
		sdk.NewAttribute("missed_blocks", fmt.Sprintf("%d", missedBlocks)),
		sdk.NewAttribute("jail_until", jailUntil.Format(time.RFC3339)),
	))

	a.logger.Warn("Validator slashed for downtime",
		"validator", consAddr.String(),
		"slashed_amount", slashedAmount.String(),
		"missed_blocks", missedBlocks,
		"jail_until", jailUntil.Format(time.RFC3339),
	)

	return &PoUWSlashResult{
		ValidatorAddress: consAddr.String(),
		SlashedAmount:    slashedAmount,
		SlashFractionBps: a.config.DowntimeSlashBps,
		Reason:           SlashReasonDowntime,
		Jailed:           true,
		JailUntil:        jailUntil,
		InfractionHeight: infractionHeight,
	}, nil
}

// SlashForDoubleSign slashes a validator for double-signing (equivocation)
func (a *SlashingModuleAdapter) SlashForDoubleSign(
	ctx sdk.Context,
	consAddr sdk.ConsAddress,
	infractionHeight int64,
	evidence *EquivocationEvidence,
) (*PoUWSlashResult, error) {
	// Check if already tombstoned
	if a.slashingKeeper != nil && a.slashingKeeper.IsTombstoned(ctx, consAddr) {
		return nil, fmt.Errorf("validator %s is already tombstoned", consAddr.String())
	}

	// Get validator
	validator, err := a.stakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
	if err != nil {
		return nil, fmt.Errorf("validator not found: %w", err)
	}

	// Get voting power at infraction height.
	power := validator.GetConsensusPower(sdk.DefaultPowerReduction)
	valAddr, addrErr := sdk.ValAddressFromBech32(validator.GetOperator())
	if addrErr == nil {
		if historicalPower, powerErr := a.stakingKeeper.GetLastValidatorPower(ctx, valAddr); powerErr == nil {
			power = historicalPower
		}
	}

	// Calculate slash fraction (50% for double-sign)
	slashFraction := sdkmath.LegacyNewDecWithPrec(a.config.DoubleSignSlashBps, 4)

	// Execute slash
	slashedAmount, err := a.stakingKeeper.Slash(ctx, consAddr, infractionHeight, power, slashFraction)
	if err != nil {
		return nil, fmt.Errorf("slash failed: %w", err)
	}

	// Tombstone the validator (cannot unjail)
	if a.config.EnableTombstoning && a.slashingKeeper != nil {
		if err := a.slashingKeeper.Tombstone(ctx, consAddr); err != nil {
			a.logger.Error("Failed to tombstone validator", "error", err, "validator", consAddr.String())
		}
	}

	// Jail for extended period
	jailUntil := ctx.BlockTime().Add(a.config.DoubleSignJailDuration)
	if a.slashingKeeper != nil {
		_ = a.slashingKeeper.JailUntil(ctx, consAddr, jailUntil)
	} else {
		_ = a.stakingKeeper.Jail(ctx, consAddr)
	}

	// Emit event
	emitEventIfEnabled(ctx, sdk.NewEvent(
		"pouw_slash_double_sign",
		sdk.NewAttribute("validator", consAddr.String()),
		sdk.NewAttribute("slashed_amount", slashedAmount.String()),
		sdk.NewAttribute("infraction_height", fmt.Sprintf("%d", infractionHeight)),
		sdk.NewAttribute("tombstoned", fmt.Sprintf("%t", a.config.EnableTombstoning)),
	))

	a.logger.Error("CRITICAL: Validator slashed for double-signing",
		"validator", consAddr.String(),
		"slashed_amount", slashedAmount.String(),
		"infraction_height", infractionHeight,
		"tombstoned", a.config.EnableTombstoning,
	)

	return &PoUWSlashResult{
		ValidatorAddress: consAddr.String(),
		SlashedAmount:    slashedAmount,
		SlashFractionBps: a.config.DoubleSignSlashBps,
		Reason:           SlashReasonDoubleSign,
		Jailed:           true,
		JailUntil:        jailUntil,
		Tombstoned:       a.config.EnableTombstoning,
		InfractionHeight: infractionHeight,
	}, nil
}

// SlashForInvalidOutput slashes a validator for submitting invalid compute output
func (a *SlashingModuleAdapter) SlashForInvalidOutput(
	ctx sdk.Context,
	consAddr sdk.ConsAddress,
	jobID string,
	infractionHeight int64,
) (*PoUWSlashResult, error) {
	// Get validator
	validator, err := a.stakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
	if err != nil {
		return nil, fmt.Errorf("validator not found: %w", err)
	}

	// Get voting power.
	power := validator.GetConsensusPower(sdk.DefaultPowerReduction)
	valAddr, addrErr := sdk.ValAddressFromBech32(validator.GetOperator())
	if addrErr == nil {
		if historicalPower, powerErr := a.stakingKeeper.GetLastValidatorPower(ctx, valAddr); powerErr == nil {
			power = historicalPower
		}
	}

	// Calculate slash fraction (100% for fraudulent invalid output)
	slashFraction := sdkmath.LegacyNewDecWithPrec(a.config.InvalidOutputSlashBps, 4)

	// Execute slash
	slashedAmount, err := a.stakingKeeper.Slash(ctx, consAddr, infractionHeight, power, slashFraction)
	if err != nil {
		return nil, fmt.Errorf("slash failed: %w", err)
	}

	// Jail the validator
	jailUntil := ctx.BlockTime().Add(a.config.InvalidOutputJailDuration)
	if a.slashingKeeper != nil {
		_ = a.slashingKeeper.JailUntil(ctx, consAddr, jailUntil)
	} else {
		_ = a.stakingKeeper.Jail(ctx, consAddr)
	}

	a.escrowFraudSlashIfEnabled(
		ctx,
		consAddr.String(),
		slashedAmount,
		string(SlashReasonInvalidOutput),
		jobID,
	)

	// Emit event
	emitEventIfEnabled(ctx, sdk.NewEvent(
		"pouw_slash_invalid_output",
		sdk.NewAttribute("validator", consAddr.String()),
		sdk.NewAttribute("slashed_amount", slashedAmount.String()),
		sdk.NewAttribute("job_id", jobID),
	))

	a.logger.Error("Validator slashed for invalid compute output",
		"validator", consAddr.String(),
		"slashed_amount", slashedAmount.String(),
		"job_id", jobID,
	)

	return &PoUWSlashResult{
		ValidatorAddress: consAddr.String(),
		SlashedAmount:    slashedAmount,
		SlashFractionBps: a.config.InvalidOutputSlashBps,
		Reason:           SlashReasonInvalidOutput,
		Jailed:           true,
		JailUntil:        jailUntil,
		InfractionHeight: infractionHeight,
		JobID:            jobID,
	}, nil
}

// SlashForCollusion slashes multiple validators for coordinated misbehavior
func (a *SlashingModuleAdapter) SlashForCollusion(
	ctx sdk.Context,
	consAddrs []sdk.ConsAddress,
	infractionHeight int64,
	evidenceDetails string,
) ([]*PoUWSlashResult, error) {
	var results []*PoUWSlashResult

	for _, consAddr := range consAddrs {
		// Get validator
		validator, err := a.stakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
		if err != nil {
			a.logger.Error("Validator not found for collusion slash",
				"validator", consAddr.String(),
				"error", err,
			)
			continue
		}

		// Get voting power.
		power := validator.GetConsensusPower(sdk.DefaultPowerReduction)
		valAddr, addrErr := sdk.ValAddressFromBech32(validator.GetOperator())
		if addrErr == nil {
			if historicalPower, powerErr := a.stakingKeeper.GetLastValidatorPower(ctx, valAddr); powerErr == nil {
				power = historicalPower
			}
		}

		// Calculate slash fraction (100% for collusion)
		slashFraction := sdkmath.LegacyNewDecWithPrec(a.config.CollusionSlashBps, 4)

		// Execute slash
		slashedAmount, err := a.stakingKeeper.Slash(ctx, consAddr, infractionHeight, power, slashFraction)
		if err != nil {
			a.logger.Error("Failed to slash for collusion",
				"validator", consAddr.String(),
				"error", err,
			)
			continue
		}

		// Tombstone for collusion (permanent ban)
		if a.config.EnableTombstoning && a.slashingKeeper != nil {
			_ = a.slashingKeeper.Tombstone(ctx, consAddr)
		}

		// Extended jail
		jailUntil := ctx.BlockTime().Add(a.config.CollusionJailDuration)
		if a.slashingKeeper != nil {
			_ = a.slashingKeeper.JailUntil(ctx, consAddr, jailUntil)
		} else {
			_ = a.stakingKeeper.Jail(ctx, consAddr)
		}

		results = append(results, &PoUWSlashResult{
			ValidatorAddress: consAddr.String(),
			SlashedAmount:    slashedAmount,
			SlashFractionBps: a.config.CollusionSlashBps,
			Reason:           SlashReasonCollusion,
			Jailed:           true,
			JailUntil:        jailUntil,
			Tombstoned:       a.config.EnableTombstoning,
			InfractionHeight: infractionHeight,
		})

		emitEventIfEnabled(ctx, sdk.NewEvent(
			"pouw_slash_collusion",
			sdk.NewAttribute("validator", consAddr.String()),
			sdk.NewAttribute("slashed_amount", slashedAmount.String()),
			sdk.NewAttribute("tombstoned", "true"),
			sdk.NewAttribute("evidence", evidenceDetails),
		))
	}

	a.logger.Error("CRITICAL: Validators slashed for collusion",
		"validator_count", len(results),
		"infraction_height", infractionHeight,
	)

	return results, nil
}

// SlashForFakeAttestation slashes a validator for submitting fake TEE attestations
func (a *SlashingModuleAdapter) SlashForFakeAttestation(
	ctx sdk.Context,
	consAddr sdk.ConsAddress,
	infractionHeight int64,
	attestationDetails string,
) (*PoUWSlashResult, error) {
	// Get validator
	validator, err := a.stakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
	if err != nil {
		return nil, fmt.Errorf("validator not found: %w", err)
	}

	// Get voting power.
	power := validator.GetConsensusPower(sdk.DefaultPowerReduction)
	valAddr, addrErr := sdk.ValAddressFromBech32(validator.GetOperator())
	if addrErr == nil {
		if historicalPower, powerErr := a.stakingKeeper.GetLastValidatorPower(ctx, valAddr); powerErr == nil {
			power = historicalPower
		}
	}

	// Calculate slash fraction (100% for fake attestation)
	slashFraction := sdkmath.LegacyNewDecWithPrec(a.config.FakeAttestationSlashBps, 4)

	// Execute slash
	slashedAmount, err := a.stakingKeeper.Slash(ctx, consAddr, infractionHeight, power, slashFraction)
	if err != nil {
		return nil, fmt.Errorf("slash failed: %w", err)
	}

	// Tombstone for fake attestation (severe violation)
	if a.config.EnableTombstoning && a.slashingKeeper != nil {
		_ = a.slashingKeeper.Tombstone(ctx, consAddr)
	}

	jailUntil := ctx.BlockTime().Add(a.config.FakeAttestationJailDuration)
	if a.slashingKeeper != nil {
		_ = a.slashingKeeper.JailUntil(ctx, consAddr, jailUntil)
	} else {
		_ = a.stakingKeeper.Jail(ctx, consAddr)
	}

	a.escrowFraudSlashIfEnabled(
		ctx,
		consAddr.String(),
		slashedAmount,
		string(SlashReasonFakeAttestation),
		attestationDetails,
	)

	emitEventIfEnabled(ctx, sdk.NewEvent(
		"pouw_slash_fake_attestation",
		sdk.NewAttribute("validator", consAddr.String()),
		sdk.NewAttribute("slashed_amount", slashedAmount.String()),
		sdk.NewAttribute("attestation_details", attestationDetails),
	))

	a.logger.Error("CRITICAL: Validator slashed for fake TEE attestation",
		"validator", consAddr.String(),
		"slashed_amount", slashedAmount.String(),
	)

	return &PoUWSlashResult{
		ValidatorAddress: consAddr.String(),
		SlashedAmount:    slashedAmount,
		SlashFractionBps: a.config.FakeAttestationSlashBps,
		Reason:           SlashReasonFakeAttestation,
		Jailed:           true,
		JailUntil:        jailUntil,
		Tombstoned:       a.config.EnableTombstoning,
		InfractionHeight: infractionHeight,
	}, nil
}

// =============================================================================
// Slash Result Types
// =============================================================================

// PoUWSlashResult contains the result of a PoUW slashing operation
type PoUWSlashResult struct {
	ValidatorAddress string
	SlashedAmount    sdkmath.Int
	SlashFractionBps int64
	Reason           SlashReason
	Jailed           bool
	JailUntil        time.Time
	Tombstoned       bool
	InfractionHeight int64
	JobID            string // For invalid output slashes
}

// =============================================================================
// Integrated Evidence Processor
// =============================================================================

// IntegratedEvidenceProcessor combines the evidence system with the slashing module
type IntegratedEvidenceProcessor struct {
	evidenceProcessor *EvidenceProcessor
	slashingAdapter   *SlashingModuleAdapter
	keeper            *Keeper
	logger            log.Logger
}

// NewIntegratedEvidenceProcessor creates a new integrated evidence processor
func NewIntegratedEvidenceProcessor(
	logger log.Logger,
	keeper *Keeper,
	stakingKeeper StakingKeeperInterface,
	slashingKeeper SlashingKeeperInterface,
	bankKeeper BankKeeperInterface,
	blockMissConfig BlockMissConfig,
	slashingConfig EvidenceSlashingConfig,
) *IntegratedEvidenceProcessor {
	// Create the base evidence processor
	evidenceProcessor := NewEvidenceProcessor(
		logger,
		keeper,
		blockMissConfig,
		slashingConfig,
	)

	// Create the slashing adapter
	adapterConfig := SlashingAdapterConfig{
		DowntimeSlashBps:        slashingConfig.DowntimeSlashBps,
		DoubleSignSlashBps:      slashingConfig.DoubleSignSlashBps,
		InvalidOutputSlashBps:   slashingConfig.InvalidOutputSlashBps,
		CollusionSlashBps:       slashingConfig.CollusionSlashBps,
		FakeAttestationSlashBps: 10000, // 100%

		DowntimeJailDuration:        slashingConfig.DowntimeJailDuration,
		DoubleSignJailDuration:      slashingConfig.DoubleSignJailDuration,
		InvalidOutputJailDuration:   7 * 24 * time.Hour,
		CollusionJailDuration:       slashingConfig.CollusionJailDuration,
		FakeAttestationJailDuration: 365 * 24 * time.Hour,

		MinSlashableTokens: sdkmath.NewInt(1000),
		EnableTombstoning:  true,
		EnableBurning:      true,
	}

	slashingAdapter := NewSlashingModuleAdapter(
		logger,
		stakingKeeper,
		slashingKeeper,
		bankKeeper,
		adapterConfig,
	)

	return &IntegratedEvidenceProcessor{
		evidenceProcessor: evidenceProcessor,
		slashingAdapter:   slashingAdapter,
		keeper:            keeper,
		logger:            logger,
	}
}

// ProcessEndBlockEvidence processes all pending evidence at EndBlock with full slashing
func (ip *IntegratedEvidenceProcessor) ProcessEndBlockEvidence(ctx sdk.Context) *IntegratedEvidenceResult {
	result := &IntegratedEvidenceResult{
		BlockHeight: ctx.BlockHeight(),
		ProcessedAt: time.Now().UTC(),
	}

	// 1. Check for downtime penalties
	downtimePenalties := ip.evidenceProcessor.blockMissTracker.CheckAndApplyDowntimePenalties(ctx)
	for _, penalty := range downtimePenalties {
		consAddr, err := sdk.ConsAddressFromBech32(penalty.ValidatorAddress)
		if err != nil {
			// Try hex decoding
			consAddr = sdk.ConsAddress([]byte(penalty.ValidatorAddress))
		}

		slashResult, err := ip.slashingAdapter.SlashForDowntime(
			ctx,
			consAddr,
			penalty.MissedBlocks,
			penalty.BlockHeight,
		)
		if err != nil {
			ip.logger.Error("Failed to slash for downtime",
				"validator", penalty.ValidatorAddress,
				"error", err,
			)
			continue
		}
		result.DowntimeSlashes = append(result.DowntimeSlashes, slashResult)
	}

	// 2. Process double-voting evidence
	equivocations := ip.evidenceProcessor.doubleVotingDetector.GetPendingEquivocations()
	var processedHashes [][32]byte
	for _, evidence := range equivocations {
		consAddr, err := sdk.ConsAddressFromBech32(evidence.ValidatorAddress)
		if err != nil {
			consAddr = sdk.ConsAddress([]byte(evidence.ValidatorAddress))
		}

		slashResult, err := ip.slashingAdapter.SlashForDoubleSign(
			ctx,
			consAddr,
			evidence.BlockHeight,
			&evidence,
		)
		if err != nil {
			ip.logger.Error("Failed to slash for double-sign",
				"validator", evidence.ValidatorAddress,
				"error", err,
			)
			continue
		}
		result.DoubleSignSlashes = append(result.DoubleSignSlashes, slashResult)
		processedHashes = append(processedHashes, evidence.EvidenceHash)
	}

	// Clear processed equivocations
	if len(processedHashes) > 0 {
		ip.evidenceProcessor.doubleVotingDetector.ClearProcessedEquivocations(processedHashes)
	}

	// 3. Prune old vote history
	ip.evidenceProcessor.doubleVotingDetector.PruneOldHistory(ctx.BlockHeight() - 1000)

	// Log summary
	if len(result.DowntimeSlashes) > 0 || len(result.DoubleSignSlashes) > 0 {
		ip.logger.Info("Integrated evidence processing complete",
			"height", ctx.BlockHeight(),
			"downtime_slashes", len(result.DowntimeSlashes),
			"double_sign_slashes", len(result.DoubleSignSlashes),
			"total_slashed", result.TotalSlashed().String(),
		)
	}

	return result
}

// RecordValidatorParticipation records validator participation
func (ip *IntegratedEvidenceProcessor) RecordValidatorParticipation(
	ctx sdk.Context,
	validatorAddr string,
	extensionHash [32]byte,
	jobOutputs map[string][32]byte,
) *EquivocationEvidence {
	return ip.evidenceProcessor.RecordValidatorParticipation(ctx, validatorAddr, extensionHash, jobOutputs)
}

// RecordValidatorMiss records a missed block
func (ip *IntegratedEvidenceProcessor) RecordValidatorMiss(ctx sdk.Context, validatorAddr string) {
	ip.evidenceProcessor.RecordValidatorMiss(ctx, validatorAddr)
}

// GetBlockMissTracker returns the block miss tracker for external use
func (ip *IntegratedEvidenceProcessor) GetBlockMissTracker() *BlockMissTracker {
	return ip.evidenceProcessor.blockMissTracker
}

// GetSlashingAdapter returns the slashing adapter for direct use
func (ip *IntegratedEvidenceProcessor) GetSlashingAdapter() *SlashingModuleAdapter {
	return ip.slashingAdapter
}

// IntegratedEvidenceResult contains the results of integrated evidence processing
type IntegratedEvidenceResult struct {
	BlockHeight          int64
	ProcessedAt          time.Time
	DowntimeSlashes      []*PoUWSlashResult
	DoubleSignSlashes    []*PoUWSlashResult
	InvalidOutputSlashes []*PoUWSlashResult
	CollusionSlashes     []*PoUWSlashResult
}

// TotalSlashed returns the total amount slashed
func (r *IntegratedEvidenceResult) TotalSlashed() sdkmath.Int {
	total := sdkmath.ZeroInt()
	for _, s := range r.DowntimeSlashes {
		total = total.Add(s.SlashedAmount)
	}
	for _, s := range r.DoubleSignSlashes {
		total = total.Add(s.SlashedAmount)
	}
	for _, s := range r.InvalidOutputSlashes {
		total = total.Add(s.SlashedAmount)
	}
	for _, s := range r.CollusionSlashes {
		total = total.Add(s.SlashedAmount)
	}
	return total
}

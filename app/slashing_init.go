// Package app provides slashing integration initialization for Aethelred.
//
// AS-16: Downtime Slashing Integration
// This file initializes the integrated evidence processor with full
// Cosmos SDK slashing module connectivity.
package app

import (
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	slashingkeeper "github.com/cosmos/cosmos-sdk/x/slashing/keeper"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// Staking Keeper Adapter
// =============================================================================

// StakingKeeperAdapter adapts the Cosmos SDK staking keeper to our interface
type StakingKeeperAdapter struct {
	keeper *stakingkeeper.Keeper
}

// NewStakingKeeperAdapter creates a new staking keeper adapter
func NewStakingKeeperAdapter(keeper *stakingkeeper.Keeper) *StakingKeeperAdapter {
	return &StakingKeeperAdapter{keeper: keeper}
}

func (a *StakingKeeperAdapter) GetValidator(ctx sdk.Context, addr sdk.ValAddress) (stakingtypes.Validator, error) {
	return a.keeper.GetValidator(ctx, addr)
}

func (a *StakingKeeperAdapter) GetValidatorByConsAddr(ctx sdk.Context, consAddr sdk.ConsAddress) (stakingtypes.Validator, error) {
	return a.keeper.GetValidatorByConsAddr(ctx, consAddr)
}

func (a *StakingKeeperAdapter) Slash(ctx sdk.Context, consAddr sdk.ConsAddress, infractionHeight int64, power int64, slashFactor sdkmath.LegacyDec) (sdkmath.Int, error) {
	return a.keeper.Slash(ctx, consAddr, infractionHeight, power, slashFactor)
}

func (a *StakingKeeperAdapter) Jail(ctx sdk.Context, consAddr sdk.ConsAddress) error {
	return a.keeper.Jail(ctx, consAddr)
}

func (a *StakingKeeperAdapter) Unjail(ctx sdk.Context, consAddr sdk.ConsAddress) error {
	return a.keeper.Unjail(ctx, consAddr)
}

func (a *StakingKeeperAdapter) GetLastValidatorPower(ctx sdk.Context, operator sdk.ValAddress) (int64, error) {
	return a.keeper.GetLastValidatorPower(ctx, operator)
}

func (a *StakingKeeperAdapter) GetAllValidators(ctx sdk.Context) ([]stakingtypes.Validator, error) {
	return a.keeper.GetAllValidators(ctx)
}

func (a *StakingKeeperAdapter) Delegation(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) (stakingtypes.Delegation, error) {
	delegation, err := a.keeper.Delegation(ctx, delAddr, valAddr)
	if err != nil {
		return stakingtypes.Delegation{}, err
	}

	typedDelegation, ok := delegation.(stakingtypes.Delegation)
	if !ok {
		return stakingtypes.Delegation{}, fmt.Errorf("unexpected delegation concrete type %T", delegation)
	}

	return typedDelegation, nil
}

// =============================================================================
// Slashing Keeper Adapter
// =============================================================================

// SlashingKeeperAdapter adapts the Cosmos SDK slashing keeper to our interface
type SlashingKeeperAdapter struct {
	keeper slashingkeeper.Keeper
}

// NewSlashingKeeperAdapter creates a new slashing keeper adapter
func NewSlashingKeeperAdapter(keeper slashingkeeper.Keeper) *SlashingKeeperAdapter {
	return &SlashingKeeperAdapter{keeper: keeper}
}

func (a *SlashingKeeperAdapter) GetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress) (slashingtypes.ValidatorSigningInfo, error) {
	return a.keeper.GetValidatorSigningInfo(ctx, address)
}

func (a *SlashingKeeperAdapter) SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info slashingtypes.ValidatorSigningInfo) error {
	return a.keeper.SetValidatorSigningInfo(ctx, address, info)
}

func (a *SlashingKeeperAdapter) GetParams(ctx sdk.Context) (slashingtypes.Params, error) {
	return a.keeper.GetParams(ctx)
}

func (a *SlashingKeeperAdapter) JailUntil(ctx sdk.Context, consAddr sdk.ConsAddress, jailTime time.Time) error {
	return a.keeper.JailUntil(ctx, consAddr, jailTime)
}

func (a *SlashingKeeperAdapter) Tombstone(ctx sdk.Context, consAddr sdk.ConsAddress) error {
	return a.keeper.Tombstone(ctx, consAddr)
}

func (a *SlashingKeeperAdapter) IsTombstoned(ctx sdk.Context, consAddr sdk.ConsAddress) bool {
	return a.keeper.IsTombstoned(ctx, consAddr)
}

// =============================================================================
// Integrated Slashing Initialization
// =============================================================================

// InitIntegratedSlashing initializes the integrated slashing system
// This connects the PoUW evidence system to the Cosmos SDK slashing module
func (app *AethelredApp) InitIntegratedSlashing() {
	logger := app.Logger()

	// Create adapters for the keepers
	stakingAdapter := NewStakingKeeperAdapter(app.StakingKeeper)
	slashingAdapter := NewSlashingKeeperAdapter(app.SlashingKeeper)

	// Configure block-miss tracking
	blockMissConfig := pouwkeeper.BlockMissConfig{
		ParticipationWindow: 10000, // ~16.6 hours with 6s blocks
		MaxMissedBlocks:     500,   // 5% miss rate triggers slashing
		JailThreshold:       1000,  // 10% miss rate triggers jailing
		DowntimeSlashBps:    500,   // 5% slash for downtime
	}

	// Configure slashing parameters
	slashingConfig := pouwkeeper.EvidenceSlashingConfig{
		DoubleSignSlashBps:     5000,  // 50%
		InvalidOutputSlashBps:  10000, // 100% (fraud)
		DowntimeSlashBps:       500,   // 5%
		CollusionSlashBps:      10000, // 100%
		DoubleSignJailDuration: 30 * 24 * time.Hour,
		DowntimeJailDuration:   24 * time.Hour,
		CollusionJailDuration:  365 * 24 * time.Hour,
	}

	// Create the integrated evidence processor
	integratedProcessor := pouwkeeper.NewIntegratedEvidenceProcessor(
		logger,
		&app.PouwKeeper,
		stakingAdapter,
		slashingAdapter,
		nil, // bank keeper integration is optional for current slashing paths
		blockMissConfig,
		slashingConfig,
	)
	if adapter := integratedProcessor.GetSlashingAdapter(); adapter != nil {
		adapter.SetInsuranceEscrowKeeper(&app.InsuranceKeeper)
	}

	// Store for use in processEndBlockEvidence
	app.integratedEvidenceProcessor = integratedProcessor

	logger.Info("Integrated slashing system initialized",
		"participation_window", blockMissConfig.ParticipationWindow,
		"max_missed_blocks", blockMissConfig.MaxMissedBlocks,
		"jail_threshold", blockMissConfig.JailThreshold,
		"downtime_slash_bps", blockMissConfig.DowntimeSlashBps,
		"double_sign_slash_bps", slashingConfig.DoubleSignSlashBps,
	)
}

// BankKeeperAdapterForSlashing is a minimal adapter for the bank keeper
type BankKeeperAdapterForSlashing struct {
	keeper interface {
		SendCoinsFromModuleToModule(ctx sdk.Context, senderModule, recipientModule string, amt sdk.Coins) error
		BurnCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error
	}
}

func (a *BankKeeperAdapterForSlashing) SendCoinsFromModuleToModule(ctx sdk.Context, senderModule, recipientModule string, amt sdk.Coins) error {
	return a.keeper.SendCoinsFromModuleToModule(ctx, senderModule, recipientModule, amt)
}

func (a *BankKeeperAdapterForSlashing) BurnCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error {
	return a.keeper.BurnCoins(ctx, moduleName, amt)
}

// =============================================================================
// Vote Extension Signer Initialization
// =============================================================================

// InitVoteExtensionSigner initializes the application-level vote extension signer
func (app *AethelredApp) InitVoteExtensionSigner(chainID string) {
	app.voteExtensionSigner = NewVoteExtensionSigner(app.Logger(), chainID)

	// If validator private key is already set, configure the signer
	if app.HasValidatorPrivateKey() {
		if err := app.voteExtensionSigner.SetSigningKey(app.validatorPrivKey); err != nil {
			app.Logger().Error("Failed to set vote extension signing key", "error", err)
		}
	}

	app.Logger().Info("Vote extension signer initialized", "chain_id", chainID)
}

// InitVoteExtensionVerifier initializes the vote extension verifier
func (app *AethelredApp) InitVoteExtensionVerifier(chainID string) {
	// Create a validator public key getter that uses the staking keeper
	getter := &StakingValidatorPubKeyGetter{
		stakingKeeper: app.StakingKeeper,
	}

	app.voteExtensionVerifier = NewVoteExtensionVerifier(app.Logger(), chainID, getter)

	app.Logger().Info("Vote extension verifier initialized", "chain_id", chainID)
}

// StakingValidatorPubKeyGetter gets validator public keys from the staking keeper
type StakingValidatorPubKeyGetter struct {
	stakingKeeper *stakingkeeper.Keeper
}

func (g *StakingValidatorPubKeyGetter) GetValidatorPubKey(ctx sdk.Context, consAddr sdk.ConsAddress) ([]byte, error) {
	validator, err := g.stakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
	if err != nil {
		return nil, err
	}

	pubKey, err := validator.ConsPubKey()
	if err != nil {
		return nil, err
	}

	return pubKey.Bytes(), nil
}

// =============================================================================
// Enhanced processEndBlockEvidence with Integrated Slashing
// =============================================================================

// processEndBlockEvidenceIntegrated processes evidence with full slashing integration
func (app *AethelredApp) processEndBlockEvidenceIntegrated(ctx sdk.Context) {
	// Use integrated processor if available
	if app.integratedEvidenceProcessor != nil {
		result := app.integratedEvidenceProcessor.ProcessEndBlockEvidence(ctx)
		if result == nil {
			return
		}

		if len(result.DowntimeSlashes) > 0 || len(result.DoubleSignSlashes) > 0 {
			app.Logger().Warn("Integrated evidence processing applied slashing",
				"height", result.BlockHeight,
				"downtime_slashes", len(result.DowntimeSlashes),
				"double_sign_slashes", len(result.DoubleSignSlashes),
				"total_slashed", result.TotalSlashed().String(),
			)

			// Update metrics
			if metrics := app.PouwKeeper.Metrics(); metrics != nil {
				metrics.SlashingPenaltiesApplied.Add(int64(len(result.DowntimeSlashes)))
				metrics.SlashingPenaltiesApplied.Add(int64(len(result.DoubleSignSlashes)))
			}
		}
		return
	}

	// Fall back to basic evidence processor
	if app.evidenceProcessor != nil {
		result := app.evidenceProcessor.ProcessEndBlockEvidence(ctx)
		if result == nil {
			return
		}

		if len(result.DowntimePenalties) > 0 || len(result.EquivocationSlashes) > 0 {
			app.Logger().Warn("Evidence processing applied penalties",
				"height", result.BlockHeight,
				"downtime_penalties", len(result.DowntimePenalties),
				"equivocation_slashes", len(result.EquivocationSlashes),
			)
		}
	}
}

// =============================================================================
// Application Fields Extension
// =============================================================================

// These fields should be added to the AethelredApp struct in app.go:
//
// // integratedEvidenceProcessor handles downtime and equivocation evidence
// // with full Cosmos SDK slashing module integration.
// integratedEvidenceProcessor *pouwkeeper.IntegratedEvidenceProcessor
//
// // voteExtensionSigner handles application-level signing of vote extensions.
// voteExtensionSigner *VoteExtensionSigner
//
// // voteExtensionVerifier verifies vote extensions from other validators.
// voteExtensionVerifier *VoteExtensionVerifier

// GetIntegratedEvidenceProcessor returns the integrated evidence processor
func (app *AethelredApp) GetIntegratedEvidenceProcessor() interface{} {
	return app.integratedEvidenceProcessor
}

// GetVoteExtensionSigner returns the vote extension signer
func (app *AethelredApp) GetVoteExtensionSigner() *VoteExtensionSigner {
	return app.voteExtensionSigner
}

// GetVoteExtensionVerifier returns the vote extension verifier
func (app *AethelredApp) GetVoteExtensionVerifier() *VoteExtensionVerifier {
	return app.voteExtensionVerifier
}

// =============================================================================
// Logging Helpers for Slashing Events
// =============================================================================

// LogSlashingEvent logs a slashing event with full context
func LogSlashingEvent(logger log.Logger, result *pouwkeeper.PoUWSlashResult) {
	logger.Warn("Validator slashed",
		"validator", result.ValidatorAddress,
		"amount", result.SlashedAmount.String(),
		"reason", string(result.Reason),
		"slash_bps", result.SlashFractionBps,
		"jailed", result.Jailed,
		"jail_until", result.JailUntil.Format(time.RFC3339),
		"tombstoned", result.Tombstoned,
		"infraction_height", result.InfractionHeight,
	)
}

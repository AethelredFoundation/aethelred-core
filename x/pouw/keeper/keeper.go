package keeper

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	sdkmath "cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
)

// Keeper manages the pouw (Proof-of-Useful-Work) module state
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	authority    string

	// External keepers
	stakingKeeper StakingKeeper
	bankKeeper    BankKeeper
	sealKeeper    sealkeeper.Keeper
	verifyKeeper  verifykeeper.Keeper

	// Liveness tracking for downtime detection
	livenessTracker *LivenessTracker

	// Metrics for observability (in-process)
	metrics *ModuleMetrics

	// Structured audit logging
	auditLogger *AuditLogger

	// State collections
	Jobs                   collections.Map[string, types.ComputeJob]
	PendingJobs            collections.Map[string, types.ComputeJob]
	RegisteredModels       collections.Map[string, types.RegisteredModel]
	ValidatorStats         collections.Map[string, types.ValidatorStats]
	ValidatorCapabilities  collections.Map[string, types.ValidatorCapability]
	ValidatorPCR0Mappings  collections.Map[string, string]
	RegisteredPCR0Set      collections.KeySet[string]
	ValidatorMeasurements  collections.Map[string, string]
	RegisteredMeasurements collections.KeySet[string]
	JobCount               collections.Item[uint64]
	Params                 collections.Item[types.Params]
}

// StakingKeeper defines the expected staking keeper interface
type StakingKeeper interface {
	GetAllValidators(ctx context.Context) ([]stakingtypes.Validator, error)
	GetValidator(ctx context.Context, addr sdk.ValAddress) (stakingtypes.Validator, error)
}

// BankKeeper defines the expected bank keeper interface for economic operations
type BankKeeper interface {
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	SendCoinsFromModuleToModule(ctx context.Context, senderModule, recipientModule string, amt sdk.Coins) error
	BurnCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	SpendableCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins
}

// NewKeeper creates a new Keeper instance
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	stakingKeeper StakingKeeper,
	bankKeeper BankKeeper,
	sealKeeper sealkeeper.Keeper,
	verifyKeeper verifykeeper.Keeper,
	authority string,
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)

	// Initialize liveness tracker for downtime detection
	// Default thresholds: 100 consecutive blocks for downtime, 500 total misses for escalation
	livenessTracker := NewLivenessTracker(100, 500)

	return Keeper{
		cdc:             cdc,
		storeService:    storeService,
		authority:       authority,
		stakingKeeper:   stakingKeeper,
		bankKeeper:      bankKeeper,
		sealKeeper:      sealKeeper,
		verifyKeeper:    verifyKeeper,
		livenessTracker: livenessTracker,
		metrics:         NewModuleMetrics(),
		auditLogger:     NewAuditLogger(10000),
		Jobs: collections.NewMap(
			sb,
			collections.NewPrefix(types.JobKeyPrefix),
			"jobs",
			collections.StringKey,
			codec.CollValue[types.ComputeJob](cdc),
		),
		PendingJobs: collections.NewMap(
			sb,
			collections.NewPrefix(types.PendingJobKeyPrefix),
			"pending_jobs",
			collections.StringKey,
			codec.CollValue[types.ComputeJob](cdc),
		),
		RegisteredModels: collections.NewMap(
			sb,
			collections.NewPrefix(types.ModelRegistryKeyPrefix),
			"registered_models",
			collections.StringKey,
			codec.CollValue[types.RegisteredModel](cdc),
		),
		ValidatorStats: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorStatsKeyPrefix),
			"validator_stats",
			collections.StringKey,
			codec.CollValue[types.ValidatorStats](cdc),
		),
		ValidatorCapabilities: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorCapabilitiesKeyPrefix),
			"validator_capabilities",
			collections.StringKey,
			codec.CollValue[types.ValidatorCapability](cdc),
		),
		ValidatorPCR0Mappings: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorPCR0KeyPrefix),
			"validator_pcr0_mappings",
			collections.StringKey,
			collections.StringValue,
		),
		RegisteredPCR0Set: collections.NewKeySet(
			sb,
			collections.NewPrefix(types.RegisteredPCR0KeyPrefix),
			"registered_pcr0_set",
			collections.StringKey,
		),
		ValidatorMeasurements: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorMeasurementKeyPrefix),
			"validator_measurements",
			collections.StringKey,
			collections.StringValue,
		),
		RegisteredMeasurements: collections.NewKeySet(
			sb,
			collections.NewPrefix(types.RegisteredMeasurementKeyPrefix),
			"registered_measurements_set",
			collections.StringKey,
		),
		JobCount: collections.NewItem(
			sb,
			collections.NewPrefix(types.JobCountKey),
			"job_count",
			collections.Uint64Value,
		),
		Params: collections.NewItem(
			sb,
			collections.NewPrefix(types.ParamsKey),
			"params",
			codec.CollValue[types.Params](cdc),
		),
	}
}

// Metrics returns the module metrics instance (may be nil in tests).
func (k Keeper) Metrics() *ModuleMetrics {
	return k.metrics
}

// AuditLogger returns the structured audit logger (may be nil in tests).
func (k Keeper) AuditLogger() *AuditLogger {
	return k.auditLogger
}

// GetAuthority returns the module's governance authority address
func (k Keeper) GetAuthority() string {
	return k.authority
}

// CountValidators returns total and online validator counts.
func (k Keeper) CountValidators(ctx context.Context) (total int, online int) {
	_ = k.ValidatorCapabilities.Walk(ctx, nil, func(_ string, cap types.ValidatorCapability) (bool, error) {
		total++
		if cap.IsOnline {
			online++
		}
		return false, nil
	})
	return total, online
}

// SubmitJob submits a new compute job for verification
func (k Keeper) SubmitJob(ctx context.Context, job *types.ComputeJob) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Validate the job
	if err := job.Validate(); err != nil {
		return fmt.Errorf("invalid job: %w", err)
	}

	// Check if model is registered
	if !k.IsModelRegistered(ctx, job.ModelHash) {
		return fmt.Errorf("model not registered: %x", job.ModelHash)
	}

	// Set block height
	job.BlockHeight = sdkCtx.BlockHeight()

	// Store in jobs collection
	if err := k.Jobs.Set(ctx, job.Id, *job); err != nil {
		return err
	}

	// Add to pending jobs queue
	if err := k.PendingJobs.Set(ctx, job.Id, *job); err != nil {
		return err
	}

	// Increment job count
	count, err := k.JobCount.Get(ctx)
	if err != nil {
		count = 0
	}
	if err := k.JobCount.Set(ctx, count+1); err != nil {
		return err
	}

	if k.metrics != nil {
		k.metrics.RecordJobSubmission()
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"job_submitted",
			sdk.NewAttribute("job_id", job.Id),
			sdk.NewAttribute("model_hash", fmt.Sprintf("%x", job.ModelHash)),
			sdk.NewAttribute("requested_by", job.RequestedBy),
			sdk.NewAttribute("proof_type", job.ProofType.String()),
			sdk.NewAttribute("purpose", job.Purpose),
		),
	)

	if k.auditLogger != nil {
		k.auditLogger.AuditJobSubmitted(sdkCtx, job.Id, fmt.Sprintf("%x", job.ModelHash), job.RequestedBy, job.ProofType.String())
	}

	return nil
}

// GetJob retrieves a job by ID
func (k Keeper) GetJob(ctx context.Context, id string) (*types.ComputeJob, error) {
	job, err := k.Jobs.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("job not found: %s", id)
	}
	jobCopy := job
	return &jobCopy, nil
}

// GetPendingJobs returns all pending jobs that are not expired.
// SECURITY FIX (P1): Uses deterministic block-height-based expiry check instead of
// time.Now() to ensure consistent results across all validators.
func (k Keeper) GetPendingJobs(ctx context.Context) []*types.ComputeJob {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	currentHeight := sdkCtx.BlockHeight()

	var jobs []*types.ComputeJob

	_ = k.PendingJobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
		// SECURITY: Use deterministic height-based expiry check
		if !job.IsExpiredAtHeight(currentHeight) {
			jobCopy := job
			jobs = append(jobs, &jobCopy)
		}
		return false, nil
	})

	return jobs
}

// UpdateJob updates an existing job
func (k Keeper) UpdateJob(ctx context.Context, job *types.ComputeJob) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Check if job exists
	exists, err := k.Jobs.Has(ctx, job.Id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("job not found: %s", job.Id)
	}

	var previous *types.ComputeJob
	if k.metrics != nil {
		if existing, err := k.Jobs.Get(ctx, job.Id); err == nil {
			jobCopy := existing
			previous = &jobCopy
		}
	}

	// Update job
	if err := k.Jobs.Set(ctx, job.Id, *job); err != nil {
		return err
	}

	// Update pending jobs if still pending
	if job.Status == types.JobStatusPending || job.Status == types.JobStatusProcessing {
		if err := k.PendingJobs.Set(ctx, job.Id, *job); err != nil {
			return err
		}
	} else {
		// Remove from pending if completed/failed
		_ = k.PendingJobs.Remove(ctx, job.Id)
	}

	if k.metrics != nil && previous != nil && previous.Status != job.Status {
		// Adjust pending/processing gauges based on transition.
		switch previous.Status {
		case types.JobStatusPending:
			k.metrics.JobsPending.Dec()
		case types.JobStatusProcessing:
			k.metrics.JobsProcessing.Dec()
		}

		switch job.Status {
		case types.JobStatusPending:
			k.metrics.JobsPending.Inc()
		case types.JobStatusProcessing:
			k.metrics.JobsProcessing.Inc()
		case types.JobStatusCompleted:
			k.metrics.JobsCompleted.Inc()
		case types.JobStatusFailed:
			k.metrics.JobsFailed.Inc()
		case types.JobStatusExpired:
			k.metrics.JobsExpired.Inc()
		}

		// Record completion time for terminal states when created_at is available.
		if (job.Status == types.JobStatusCompleted || job.Status == types.JobStatusFailed || job.Status == types.JobStatusExpired) &&
			k.metrics.JobCompletionTime != nil && previous.CreatedAt != nil {
			duration := sdkCtx.BlockTime().Sub(previous.CreatedAt.AsTime())
			if duration < 0 {
				duration = 0
			}
			k.metrics.JobCompletionTime.Record(duration)
		}
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"job_updated",
			sdk.NewAttribute("job_id", job.Id),
			sdk.NewAttribute("status", job.Status.String()),
		),
	)

	if k.auditLogger != nil && previous != nil && previous.Status != job.Status {
		switch job.Status {
		case types.JobStatusFailed, types.JobStatusExpired:
			k.auditLogger.AuditJobFailed(sdkCtx, job.Id, job.Status.String())
		}
	}

	return nil
}

// CompleteJob marks a job as completed and creates a Digital Seal
func (k Keeper) CompleteJob(ctx context.Context, jobID string, outputHash []byte, verificationResults []types.VerificationResult) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Get the job
	job, err := k.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	model, _ := k.GetRegisteredModel(ctx, job.ModelHash)
	totalUWU, vto, modelParamSize := calculateUsefulWorkUnitsVTO(job, model, outputHash)
	if totalUWU > 0 {
		job.UsefulWorkUnits = totalUWU
		if job.Metadata == nil {
			job.Metadata = make(map[string]string)
		}
		job.Metadata[workMetadataFormulaKey] = workFormulaVTOByParamSize
		job.Metadata[workMetadataVTOKey] = strconv.FormatUint(vto, 10)
		job.Metadata[workMetadataModelParamSizeKey] = strconv.FormatUint(modelParamSize, 10)
	}

	successfulVerifications := 0
	for i := range verificationResults {
		if verificationResults[i].Success {
			successfulVerifications++
		}
	}
	if successfulVerifications > 0 && totalUWU > 0 {
		perVerifier := totalUWU / uint64(successfulVerifications)
		remainder := totalUWU % uint64(successfulVerifications)
		for i := range verificationResults {
			if !verificationResults[i].Success {
				continue
			}
			verificationResults[i].UwuContribution = perVerifier
			if remainder > 0 {
				verificationResults[i].UwuContribution++
				remainder--
			}
		}
	}

	// Add verification results
	for _, result := range verificationResults {
		job.AddVerificationResult(result)
	}

	// Create Digital Seal
	seal := sealtypes.NewDigitalSeal(
		job.ModelHash,
		job.InputHash,
		outputHash,
		sdkCtx.BlockHeight(),
		job.RequestedBy,
		job.Purpose,
	)

	// Add TEE attestations from verification results
	for _, result := range verificationResults {
		if result.Success && result.AttestationType == "tee" {
			attestation := &sealtypes.TEEAttestation{
				ValidatorAddress: result.ValidatorAddress,
				Platform:         result.TeePlatform,
				Quote:            result.AttestationData,
				Timestamp:        result.Timestamp,
			}
			seal.AddAttestation(attestation)
		}
	}

	// Activate the seal
	seal.Activate()

	// Store the seal
	if err := k.sealKeeper.CreateSeal(ctx, seal); err != nil {
		return fmt.Errorf("failed to create seal: %w", err)
	}

	// Mark job as completed (state machine enforces valid transition)
	if err := job.MarkCompleted(outputHash, seal.Id); err != nil {
		return fmt.Errorf("invalid job state transition: %w", err)
	}

	// Update job
	if err := k.UpdateJob(ctx, job); err != nil {
		return err
	}

	// Update validator stats and enforce economics (rewards + slashing)
	params, _ := k.GetParams(ctx)
	verificationReward, rewardErr := sdk.ParseCoinNormalized(params.VerificationReward)
	slashingPenalty, slashErr := sdk.ParseCoinNormalized(params.SlashingPenalty)

	successfulValidators := 0
	for _, result := range verificationResults {
		if k.metrics != nil {
			k.metrics.RecordVerification(time.Duration(result.ExecutionTimeMs)*time.Millisecond, result.Success)
			switch strings.ToLower(result.AttestationType) {
			case "tee":
				k.metrics.VerificationsTEE.Inc()
			case "zkml":
				k.metrics.VerificationsZKML.Inc()
			case "hybrid":
				k.metrics.VerificationsHybrid.Inc()
			}
		}

		stats, _ := k.GetValidatorStats(ctx, result.ValidatorAddress)
		if stats == nil {
			stats = types.NewValidatorStats(result.ValidatorAddress)
		}
		if result.Success {
			stats.RecordSuccess(result.ExecutionTimeMs)
			successfulValidators++

			// Distribute verification reward from the pouw module account
			if rewardErr == nil && verificationReward.IsPositive() && k.hasMinimumValidatorStake(ctx, result.ValidatorAddress) {
				valAddr, addrErr := sdk.AccAddressFromBech32(result.ValidatorAddress)
				if addrErr == nil {
					if sendErr := k.bankKeeper.SendCoinsFromModuleToAccount(
						ctx, types.ModuleName, valAddr, sdk.NewCoins(verificationReward),
					); sendErr != nil {
						sdkCtx.Logger().Warn("Failed to distribute verification reward",
							"validator", result.ValidatorAddress,
							"error", sendErr,
						)
					} else {
						sdkCtx.EventManager().EmitEvent(
							sdk.NewEvent(
								"verification_reward",
								sdk.NewAttribute("validator", result.ValidatorAddress),
								sdk.NewAttribute("reward", verificationReward.String()),
								sdk.NewAttribute("job_id", jobID),
							),
						)
					}
				}
			}
			if rewardErr == nil && verificationReward.IsPositive() && !k.hasMinimumValidatorStake(ctx, result.ValidatorAddress) {
				sdkCtx.Logger().Warn("Verification reward withheld: validator below minimum bonded stake",
					"validator", result.ValidatorAddress,
					"required_uaeth", MinimumValidatorStakeUAETH().String(),
				)
			}
		} else {
			stats.RecordFailure()

			// Apply slashing penalty for incorrect verification.
			// First attempt to slash locked bonded stake via staking keeper.
			// If staking slash path is unavailable, fallback to account-balance slashing.
			if slashErr == nil && slashingPenalty.IsPositive() {
				slashFactor := sdkmath.LegacyMustNewDecFromStr("0.05")
				if slashedAmount, applied, slashStakeErr := k.slashValidatorBondedStake(ctx, result.ValidatorAddress, slashFactor); slashStakeErr == nil && applied {
					sdkCtx.EventManager().EmitEvent(
						sdk.NewEvent(
							"verification_slashed",
							sdk.NewAttribute("validator", result.ValidatorAddress),
							sdk.NewAttribute("penalty", slashedAmount.String()),
							sdk.NewAttribute("job_id", jobID),
							sdk.NewAttribute("reason", result.ErrorMessage),
							sdk.NewAttribute("slash_source", "bonded_stake"),
						),
					)
					if k.metrics != nil {
						k.metrics.SlashingPenaltiesApplied.Inc()
					}
					if k.auditLogger != nil {
						k.auditLogger.AuditSlashingApplied(sdkCtx, result.ValidatorAddress, "invalid_output", "high", slashedAmount.String(), jobID)
					}
					_ = k.SetValidatorStats(ctx, stats)
					continue
				}

				valAddr, addrErr := sdk.AccAddressFromBech32(result.ValidatorAddress)
				if addrErr == nil {
					// Check if validator has sufficient balance to slash
					spendable := k.bankKeeper.SpendableCoins(ctx, valAddr)
					penaltyCoins := sdk.NewCoins(slashingPenalty)

					if spendable.IsAllGTE(penaltyCoins) {
						// Transfer penalty from validator to pouw module, then burn
						if sendErr := k.bankKeeper.SendCoinsFromAccountToModule(
							ctx, valAddr, types.ModuleName, penaltyCoins,
						); sendErr != nil {
							sdkCtx.Logger().Warn("Failed to collect slashing penalty",
								"validator", result.ValidatorAddress,
								"error", sendErr,
							)
							if k.metrics != nil {
								k.metrics.SlashingPenaltiesFailed.Inc()
							}
						} else {
							// Burn the slashed tokens
							if burnErr := k.bankKeeper.BurnCoins(ctx, types.ModuleName, penaltyCoins); burnErr != nil {
								sdkCtx.Logger().Warn("Failed to burn slashed tokens",
									"validator", result.ValidatorAddress,
									"error", burnErr,
								)
								if k.metrics != nil {
									k.metrics.SlashingPenaltiesFailed.Inc()
								}
							}
							sdkCtx.EventManager().EmitEvent(
								sdk.NewEvent(
									"verification_slashed",
									sdk.NewAttribute("validator", result.ValidatorAddress),
									sdk.NewAttribute("penalty", slashingPenalty.String()),
									sdk.NewAttribute("job_id", jobID),
									sdk.NewAttribute("reason", result.ErrorMessage),
									sdk.NewAttribute("slash_source", "account_balance_fallback"),
								),
							)
							if k.metrics != nil {
								k.metrics.SlashingPenaltiesApplied.Inc()
							}
							if k.auditLogger != nil {
								k.auditLogger.AuditSlashingApplied(sdkCtx, result.ValidatorAddress, "invalid_output", "high", slashingPenalty.String(), jobID)
							}
						}
					} else {
						sdkCtx.Logger().Warn("Validator has insufficient funds for slashing",
							"validator", result.ValidatorAddress,
							"required", slashingPenalty.String(),
							"available", spendable.String(),
						)
					}
				}
			}
		}
		_ = k.SetValidatorStats(ctx, stats)
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"job_completed",
			sdk.NewAttribute("job_id", jobID),
			sdk.NewAttribute("seal_id", seal.Id),
			sdk.NewAttribute("output_hash", fmt.Sprintf("%x", outputHash)),
			sdk.NewAttribute("validator_count", fmt.Sprintf("%d", len(verificationResults))),
		),
	)

	if k.auditLogger != nil {
		k.auditLogger.AuditJobCompleted(sdkCtx, jobID, seal.Id, fmt.Sprintf("%x", outputHash), successfulValidators)
	}

	return nil
}

// RegisterModel registers a new AI model
func (k Keeper) RegisterModel(ctx context.Context, model *types.RegisteredModel) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Check if model already registered
	modelHashKey := fmt.Sprintf("%x", model.ModelHash)
	exists, err := k.RegisteredModels.Has(ctx, modelHashKey)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("model already registered: %x", model.ModelHash)
	}

	// Store model
	if err := k.RegisteredModels.Set(ctx, modelHashKey, *model); err != nil {
		return err
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"model_registered",
			sdk.NewAttribute("model_hash", modelHashKey),
			sdk.NewAttribute("model_id", model.ModelId),
			sdk.NewAttribute("name", model.Name),
			sdk.NewAttribute("owner", model.Owner),
		),
	)

	return nil
}

// IsModelRegistered checks if a model is registered
func (k Keeper) IsModelRegistered(ctx context.Context, modelHash []byte) bool {
	modelHashKey := fmt.Sprintf("%x", modelHash)
	exists, _ := k.RegisteredModels.Has(ctx, modelHashKey)
	return exists
}

// GetRegisteredModel retrieves a registered model
func (k Keeper) GetRegisteredModel(ctx context.Context, modelHash []byte) (*types.RegisteredModel, error) {
	modelHashKey := fmt.Sprintf("%x", modelHash)
	model, err := k.RegisteredModels.Get(ctx, modelHashKey)
	if err != nil {
		return nil, fmt.Errorf("model not found: %x", modelHash)
	}
	modelCopy := model
	return &modelCopy, nil
}

// GetValidatorStats retrieves validator statistics
func (k Keeper) GetValidatorStats(ctx context.Context, validatorAddr string) (*types.ValidatorStats, error) {
	stats, err := k.ValidatorStats.Get(ctx, validatorAddr)
	if err != nil {
		return nil, fmt.Errorf("validator stats not found: %s", validatorAddr)
	}
	statsCopy := stats
	return &statsCopy, nil
}

// SetValidatorStats updates validator statistics
func (k Keeper) SetValidatorStats(ctx context.Context, stats *types.ValidatorStats) error {
	return k.ValidatorStats.Set(ctx, stats.ValidatorAddress, *stats)
}

// RegisterValidatorCapability registers or updates a validator's capabilities.
func (k Keeper) RegisterValidatorCapability(ctx context.Context, cap *types.ValidatorCapability) error {
	if cap == nil || cap.Address == "" {
		return fmt.Errorf("validator capability must include address")
	}

	if !k.hasMinimumValidatorStake(ctx, cap.Address) {
		return fmt.Errorf(
			"validator %s does not meet minimum bonded stake requirement: need at least %s uaeth",
			cap.Address,
			MinimumValidatorStakeUAETH().String(),
		)
	}

	registrations := ExtractTEETrustedMeasurementsFromPlatforms(cap.TeePlatforms)
	for _, registration := range registrations {
		if err := k.RegisterValidatorMeasurement(
			ctx,
			cap.Address,
			registration.Platform,
			registration.MeasurementHex,
		); err != nil {
			return fmt.Errorf("failed to register validator TEE measurement: %w", err)
		}
	}

	return k.ValidatorCapabilities.Set(ctx, cap.Address, *cap)
}

// GetValidatorCapability retrieves a validator's capabilities.
func (k Keeper) GetValidatorCapability(ctx context.Context, validatorAddr string) (*types.ValidatorCapability, error) {
	cap, err := k.ValidatorCapabilities.Get(ctx, validatorAddr)
	if err != nil {
		return nil, fmt.Errorf("validator capability not found: %s", validatorAddr)
	}
	capCopy := cap
	return &capCopy, nil
}

// GetAllValidatorCapabilities returns all registered validator capabilities.
func (k Keeper) GetAllValidatorCapabilities(ctx context.Context) ([]*types.ValidatorCapability, error) {
	var caps []*types.ValidatorCapability
	_ = k.ValidatorCapabilities.Walk(ctx, nil, func(id string, cap types.ValidatorCapability) (bool, error) {
		capCopy := cap
		caps = append(caps, &capCopy)
		return false, nil
	})
	return caps, nil
}

// GetParams returns the module parameters
func (k Keeper) GetParams(ctx context.Context) (*types.Params, error) {
	params, err := k.Params.Get(ctx)
	if err != nil {
		return types.DefaultParams(), nil
	}
	paramsCopy := params
	return &paramsCopy, nil
}

// SetParams sets the module parameters
func (k Keeper) SetParams(ctx context.Context, params *types.Params) error {
	if params == nil {
		return fmt.Errorf("params cannot be nil")
	}
	return k.Params.Set(ctx, *params)
}

// InitGenesis initializes the module's state from genesis
func (k Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	// Set params
	params := gs.Params
	if params == nil {
		params = types.DefaultParams()
	}
	if err := k.SetParams(ctx, params); err != nil {
		return err
	}

	// Set jobs
	for _, job := range gs.Jobs {
		if job == nil {
			continue
		}
		if err := k.Jobs.Set(ctx, job.Id, *job); err != nil {
			return err
		}
		if job.Status == types.JobStatusPending || job.Status == types.JobStatusProcessing {
			if err := k.PendingJobs.Set(ctx, job.Id, *job); err != nil {
				return err
			}
		}
	}

	// Set registered models
	for _, model := range gs.RegisteredModels {
		if model == nil {
			continue
		}
		modelHashKey := fmt.Sprintf("%x", model.ModelHash)
		if err := k.RegisteredModels.Set(ctx, modelHashKey, *model); err != nil {
			return err
		}
	}

	// Set validator stats
	for _, stats := range gs.ValidatorStats {
		if stats == nil {
			continue
		}
		if err := k.ValidatorStats.Set(ctx, stats.ValidatorAddress, *stats); err != nil {
			return err
		}
	}

	// Set validator capabilities
	for _, cap := range gs.ValidatorCapabilities {
		if cap == nil {
			continue
		}
		if err := k.ValidatorCapabilities.Set(ctx, cap.Address, *cap); err != nil {
			return err
		}
		registrations := ExtractTEETrustedMeasurementsFromPlatforms(cap.TeePlatforms)
		for _, registration := range registrations {
			if err := k.RegisterValidatorMeasurement(
				ctx,
				cap.Address,
				registration.Platform,
				registration.MeasurementHex,
			); err != nil {
				return err
			}
		}
	}

	// Set job count
	if err := k.JobCount.Set(ctx, uint64(len(gs.Jobs))); err != nil {
		return err
	}

	return nil
}

// ExportGenesis exports the module's state
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	var jobs []*types.ComputeJob
	_ = k.Jobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
		jobCopy := job
		jobs = append(jobs, &jobCopy)
		return false, nil
	})

	var models []*types.RegisteredModel
	_ = k.RegisteredModels.Walk(ctx, nil, func(id string, model types.RegisteredModel) (bool, error) {
		modelCopy := model
		models = append(models, &modelCopy)
		return false, nil
	})

	var stats []*types.ValidatorStats
	_ = k.ValidatorStats.Walk(ctx, nil, func(id string, s types.ValidatorStats) (bool, error) {
		statsCopy := s
		stats = append(stats, &statsCopy)
		return false, nil
	})

	var caps []*types.ValidatorCapability
	_ = k.ValidatorCapabilities.Walk(ctx, nil, func(id string, cap types.ValidatorCapability) (bool, error) {
		capCopy := cap
		caps = append(caps, &capCopy)
		return false, nil
	})

	return &types.GenesisState{
		Params:                params,
		Jobs:                  jobs,
		RegisteredModels:      models,
		ValidatorStats:        stats,
		ValidatorCapabilities: caps,
	}, nil
}

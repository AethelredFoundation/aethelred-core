package keeper

import (
	"context"
	"fmt"
	"strings"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// reservedMetadataPrefix defines metadata key prefixes reserved for internal use.
// User-supplied metadata keys starting with these prefixes will be rejected.
const reservedMetadataPrefix = "scheduler."

type msgServer struct {
	types.UnimplementedMsgServer
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = (*msgServer)(nil)

// SubmitJob handles MsgSubmitJob.
func (k msgServer) SubmitJob(goCtx context.Context, msg *types.MsgSubmitJob) (*types.MsgSubmitJobResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Default fee to the module base fee if configured; fallback to zero if parsing fails.
	fee := sdk.NewCoin("uaeth", sdkmath.NewInt(0))
	if params, err := k.GetParams(ctx); err == nil && params.BaseJobFee != "" {
		if parsed, err := sdk.ParseCoinNormalized(params.BaseJobFee); err == nil {
			fee = parsed
		}
	}

	// SECURITY FIX (P0): Use deterministic block time instead of time.Now()
	// This ensures all validators derive the same job ID and timestamps.
	job := types.NewComputeJobWithBlockTime(
		msg.ModelHash,
		msg.InputHash,
		msg.Creator,
		msg.ProofType,
		msg.Purpose,
		fee,
		ctx.BlockHeight(),
		ctx.BlockTime(), // Deterministic: same across all validators
	)

	job.ModelId = msg.ModelId
	job.InputDataUri = msg.InputDataUri
	job.Priority = msg.Priority

	// SECURITY FIX (P2): Validate and copy metadata, rejecting reserved prefixes
	if len(msg.Metadata) > 0 {
		if job.Metadata == nil {
			job.Metadata = make(map[string]string, len(msg.Metadata))
		}
		for key, value := range msg.Metadata {
			// Reject reserved keys that could interfere with scheduler internals
			if strings.HasPrefix(key, reservedMetadataPrefix) {
				return nil, fmt.Errorf("metadata key %q uses reserved prefix %q", key, reservedMetadataPrefix)
			}
			job.Metadata[key] = value
		}
	}

	if err := k.Keeper.SubmitJob(ctx, job); err != nil {
		return nil, err
	}

	return &types.MsgSubmitJobResponse{JobId: job.Id}, nil
}

// RegisterModel handles MsgRegisterModel.
func (k msgServer) RegisterModel(goCtx context.Context, msg *types.MsgRegisterModel) (*types.MsgRegisterModelResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	model := types.NewRegisteredModel(
		msg.ModelHash,
		msg.ModelId,
		msg.Name,
		msg.Description,
		msg.Version,
		msg.Architecture,
		msg.Owner,
	)

	model.InputSchema = msg.InputSchema
	model.OutputSchema = msg.OutputSchema
	model.CircuitHash = msg.CircuitHash
	model.VerifyingKeyHash = msg.VerifyingKeyHash
	model.TeeMeasurement = msg.TeeMeasurement
	model.AllowedPurposes = msg.AllowedPurposes

	if err := k.Keeper.RegisterModel(ctx, model); err != nil {
		return nil, err
	}

	return &types.MsgRegisterModelResponse{ModelHash: model.ModelHash}, nil
}

// CancelJob handles MsgCancelJob.
func (k msgServer) CancelJob(goCtx context.Context, msg *types.MsgCancelJob) (*types.MsgCancelJobResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	job, err := k.Keeper.GetJob(ctx, msg.JobId)
	if err != nil {
		return nil, err
	}

	if job.RequestedBy != msg.Creator {
		return nil, fmt.Errorf("unauthorized: only job creator can cancel")
	}

	if job.Status != types.JobStatusPending {
		return nil, fmt.Errorf("job is not pending: %s", job.Status)
	}

	if err := job.MarkFailed(); err != nil {
		return nil, fmt.Errorf("failed to cancel job: %w", err)
	}
	if job.Metadata == nil {
		job.Metadata = map[string]string{}
	}
	job.Metadata["cancelled_by"] = msg.Creator
	// SECURITY FIX: Use deterministic block time instead of time.Now()
	job.Metadata["cancelled_at"] = ctx.BlockTime().UTC().Format("2006-01-02T15:04:05Z")

	if err := k.Keeper.UpdateJob(ctx, job); err != nil {
		return nil, err
	}

	if metrics := k.Keeper.Metrics(); metrics != nil {
		metrics.JobsCancelled.Inc()
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"job_cancelled",
			sdk.NewAttribute("job_id", job.Id),
			sdk.NewAttribute("creator", msg.Creator),
		),
	)

	return &types.MsgCancelJobResponse{}, nil
}

// RegisterValidatorCapability handles MsgRegisterValidatorCapability.
func (k msgServer) RegisterValidatorCapability(goCtx context.Context, msg *types.MsgRegisterValidatorCapability) (*types.MsgRegisterValidatorCapabilityResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	maxInt := int64(^uint(0) >> 1)
	if msg.MaxConcurrentJobs > maxInt {
		return nil, fmt.Errorf("max_concurrent_jobs exceeds platform limit")
	}

	currentJobs := int64(0)
	reputation := int64(50)
	if existing, err := k.Keeper.GetValidatorCapability(ctx, msg.Creator); err == nil && existing != nil {
		currentJobs = existing.CurrentJobs
		reputation = existing.ReputationScore
	}

	cap := &types.ValidatorCapability{
		Address:           msg.Creator,
		TeePlatforms:      msg.TeePlatforms,
		ZkmlSystems:       msg.ZkmlSystems,
		MaxConcurrentJobs: msg.MaxConcurrentJobs,
		CurrentJobs:       currentJobs,
		IsOnline:          msg.IsOnline,
		// SECURITY FIX: Use deterministic block time instead of timestamppb.Now()
		LastSeen:        timestamppb.New(ctx.BlockTime()),
		ReputationScore: reputation,
	}

	if err := k.Keeper.RegisterValidatorCapability(ctx, cap); err != nil {
		return nil, err
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"validator_capability_registered",
			sdk.NewAttribute("validator", msg.Creator),
			sdk.NewAttribute("max_concurrent_jobs", fmt.Sprintf("%d", cap.MaxConcurrentJobs)),
			sdk.NewAttribute("is_online", fmt.Sprintf("%t", cap.IsOnline)),
		),
	)

	return &types.MsgRegisterValidatorCapabilityResponse{}, nil
}

// RegisterValidatorPCR0 handles MsgRegisterValidatorPCR0.
func (k msgServer) RegisterValidatorPCR0(goCtx context.Context, msg *types.MsgRegisterValidatorPCR0) (*types.MsgRegisterValidatorPCR0Response, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	if err := k.Keeper.RegisterValidatorPCR0(ctx, msg.ValidatorAddress, msg.Pcr0Hex); err != nil {
		return nil, err
	}

	return &types.MsgRegisterValidatorPCR0Response{
		ValidatorAddress: msg.ValidatorAddress,
		Pcr0Hex:          msg.Pcr0Hex,
	}, nil
}

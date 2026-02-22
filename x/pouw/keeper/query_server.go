package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// queryServer implements the pouw module's gRPC QueryServer.
type queryServer struct {
	types.UnimplementedQueryServer
	Keeper
}

// NewQueryServerImpl returns an implementation of the pouw module QueryServer.
func NewQueryServerImpl(keeper Keeper) types.QueryServer {
	return &queryServer{Keeper: keeper}
}

var _ types.QueryServer = (*queryServer)(nil)

// Job returns a single compute job by ID.
func (q queryServer) Job(goCtx context.Context, req *types.QueryJobRequest) (*types.QueryJobResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.JobId == "" {
		return nil, fmt.Errorf("job_id cannot be empty")
	}

	job, err := q.Keeper.GetJob(goCtx, req.JobId)
	if err != nil {
		return nil, fmt.Errorf("job not found: %s", req.JobId)
	}

	return &types.QueryJobResponse{Job: job}, nil
}

// Jobs returns all compute jobs (paginated via marker).
func (q queryServer) Jobs(goCtx context.Context, req *types.QueryJobsRequest) (*types.QueryJobsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	var jobs []*types.ComputeJob
	_ = q.Keeper.Jobs.Walk(goCtx, nil, func(id string, job types.ComputeJob) (bool, error) {
		jobCopy := job
		jobs = append(jobs, &jobCopy)
		return false, nil
	})

	return &types.QueryJobsResponse{Jobs: jobs}, nil
}

// PendingJobs returns all pending/processing compute jobs.
func (q queryServer) PendingJobs(goCtx context.Context, req *types.QueryPendingJobsRequest) (*types.QueryPendingJobsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	pendingJobs := q.Keeper.GetPendingJobs(goCtx)

	return &types.QueryPendingJobsResponse{Jobs: pendingJobs}, nil
}

// Model returns a registered model by its hash.
func (q queryServer) Model(goCtx context.Context, req *types.QueryModelRequest) (*types.QueryModelResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if len(req.ModelHash) == 0 {
		return nil, fmt.Errorf("model_hash cannot be empty")
	}

	model, err := q.Keeper.GetRegisteredModel(goCtx, req.ModelHash)
	if err != nil {
		return nil, fmt.Errorf("model not found: %x", req.ModelHash)
	}

	return &types.QueryModelResponse{Model: model}, nil
}

// ValidatorStats returns the stats for a specific validator.
func (q queryServer) ValidatorStats(goCtx context.Context, req *types.QueryValidatorStatsRequest) (*types.QueryValidatorStatsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.ValidatorAddress == "" {
		return nil, fmt.Errorf("validator_address cannot be empty")
	}

	stats, err := q.Keeper.GetValidatorStats(goCtx, req.ValidatorAddress)
	if err != nil {
		return nil, fmt.Errorf("validator stats not found: %s", req.ValidatorAddress)
	}

	return &types.QueryValidatorStatsResponse{Stats: stats}, nil
}

// Params returns the module parameters.
func (q queryServer) Params(goCtx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	params, err := q.Keeper.GetParams(goCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get params: %w", err)
	}

	return &types.QueryParamsResponse{Params: params}, nil
}

// ValidatorPCR0 returns a validator's registered Nitro PCR0 mapping.
func (q queryServer) ValidatorPCR0(goCtx context.Context, req *types.QueryValidatorPCR0Request) (*types.QueryValidatorPCR0Response, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.ValidatorAddress == "" {
		return nil, fmt.Errorf("validator_address cannot be empty")
	}

	pcr0, err := q.Keeper.ValidatorPCR0Mappings.Get(goCtx, req.ValidatorAddress)
	if err != nil {
		return nil, fmt.Errorf("validator PCR0 mapping not found: %s", req.ValidatorAddress)
	}

	return &types.QueryValidatorPCR0Response{
		ValidatorAddress: req.ValidatorAddress,
		Pcr0Hex:          pcr0,
	}, nil
}

// IsPCR0Registered checks whether a PCR0 hash is globally trusted.
func (q queryServer) IsPCR0Registered(goCtx context.Context, req *types.QueryIsPCR0RegisteredRequest) (*types.QueryIsPCR0RegisteredResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.Pcr0Hex == "" {
		return nil, fmt.Errorf("pcr0_hex cannot be empty")
	}

	normalized, err := normalizePCR0Hex(req.Pcr0Hex)
	if err != nil {
		return nil, err
	}

	registered, err := q.Keeper.RegisteredPCR0Set.Has(goCtx, normalized)
	if err != nil {
		return nil, fmt.Errorf("failed to query PCR0 registry: %w", err)
	}

	return &types.QueryIsPCR0RegisteredResponse{
		Pcr0Hex:    normalized,
		Registered: registered,
	}, nil
}

// ---------------------------------------------------------------------------
// Module health & metrics queries (non-proto, for operator dashboards)
// ---------------------------------------------------------------------------

// QueryModuleStatusResponse provides a comprehensive module status for
// operator dashboards and monitoring.
type QueryModuleStatusResponse struct {
	Params               *types.Params `json:"params"`
	JobCount             uint64        `json:"job_count"`
	PendingJobCount      int           `json:"pending_job_count"`
	ValidatorCount       int           `json:"validator_count"`
	OnlineValidatorCount int           `json:"online_validator_count"`
	BlockHeight          int64         `json:"block_height"`
}

// GetModuleStatus returns a comprehensive module status snapshot.
// This is a helper for CLI/REST endpoints, not a gRPC method.
func (k Keeper) GetModuleStatus(ctx context.Context) (*QueryModuleStatusResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	jobCount, err := k.JobCount.Get(ctx)
	if err != nil {
		jobCount = 0
	}

	pendingJobs := k.GetPendingJobs(ctx)

	// Count validators and online validators
	totalValidators := 0
	onlineValidators := 0
	_ = k.ValidatorCapabilities.Walk(ctx, nil, func(_ string, cap types.ValidatorCapability) (bool, error) {
		totalValidators++
		if cap.IsOnline {
			onlineValidators++
		}
		return false, nil
	})

	return &QueryModuleStatusResponse{
		Params:               params,
		JobCount:             jobCount,
		PendingJobCount:      len(pendingJobs),
		ValidatorCount:       totalValidators,
		OnlineValidatorCount: onlineValidators,
		BlockHeight:          sdkCtx.BlockHeight(),
	}, nil
}

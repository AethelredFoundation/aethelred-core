package keeper

import (
	"context"
	"fmt"

	"github.com/aethelred/aethelred/x/seal/types"
)

type queryServer struct {
	types.UnimplementedQueryServer
	Keeper
}

// NewQueryServerImpl returns an implementation of the QueryServer interface
func NewQueryServerImpl(keeper Keeper) types.QueryServer {
	return &queryServer{Keeper: keeper}
}

var _ types.QueryServer = queryServer{}

func (q queryServer) Seal(ctx context.Context, req *types.QuerySealRequest) (*types.QuerySealResponse, error) {
	if req.SealId == "" {
		return nil, fmt.Errorf("seal_id is required")
	}

	seal, err := q.Keeper.GetSeal(ctx, req.SealId)
	if err != nil {
		return nil, err
	}

	return &types.QuerySealResponse{
		Seal: seal,
	}, nil
}

func (q queryServer) Seals(ctx context.Context, req *types.QuerySealsRequest) (*types.QuerySealsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	offset := int(req.Offset)
	if offset < 0 {
		offset = 0
	}

	seals, err := q.Keeper.ListSeals(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	total, err := q.Keeper.GetSealCount(ctx)
	if err != nil {
		return nil, err
	}

	return &types.QuerySealsResponse{
		Seals: seals,
		Total: total,
	}, nil
}

func (q queryServer) SealsByModel(ctx context.Context, req *types.QuerySealsByModelRequest) (*types.QuerySealsByModelResponse, error) {
	if len(req.ModelHash) == 0 {
		return nil, fmt.Errorf("model_hash is required")
	}

	seals, err := q.Keeper.ListSealsByModel(ctx, req.ModelHash)
	if err != nil {
		return nil, err
	}

	return &types.QuerySealsByModelResponse{
		Seals: seals,
	}, nil
}

func (q queryServer) VerifySeal(ctx context.Context, req *types.QueryVerifySealRequest) (*types.QueryVerifySealResponse, error) {
	if req.SealId == "" {
		return nil, fmt.Errorf("seal_id is required")
	}

	seal, err := q.Keeper.GetSeal(ctx, req.SealId)
	if err != nil {
		return &types.QueryVerifySealResponse{
			Valid:            false,
			VerificationType: "none",
			Status:           "not_found",
		}, nil
	}

	valid, err := q.Keeper.VerifySeal(ctx, req.SealId)
	if err != nil {
		return nil, err
	}

	return &types.QueryVerifySealResponse{
		Valid:            valid,
		VerificationType: seal.GetVerificationType(),
		Status:           seal.Status.String(),
	}, nil
}

func (q queryServer) Params(ctx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	params, err := q.Keeper.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	return &types.QueryParamsResponse{
		Params: params,
	}, nil
}

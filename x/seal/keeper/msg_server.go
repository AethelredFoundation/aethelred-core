package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

type msgServer struct {
	types.UnimplementedMsgServer
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// CreateSeal handles MsgCreateSeal
func (k msgServer) CreateSeal(goCtx context.Context, msg *types.MsgCreateSeal) (*types.MsgCreateSealResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Create the seal object
	seal := types.NewDigitalSeal(
		msg.ModelCommitment,
		msg.InputCommitment,
		msg.OutputCommitment,
		ctx.BlockHeight(),
		msg.Creator,
		msg.Purpose,
	)

	// Add TEE attestations if provided
	for _, attestation := range msg.TeeAttestations {
		seal.AddAttestation(attestation)
	}

	// Set ZK proof if provided
	if msg.ZkProof != nil {
		seal.SetZKProof(msg.ZkProof)
	}

	// Activate if verification is present
	if seal.IsVerified() {
		seal.Activate()
	}

	// Store the seal
	if err := k.Keeper.CreateSeal(ctx, seal); err != nil {
		return nil, err
	}

	return &types.MsgCreateSealResponse{
		SealId: seal.Id,
	}, nil
}

// RevokeSeal handles MsgRevokeSeal
func (k msgServer) RevokeSeal(goCtx context.Context, msg *types.MsgRevokeSeal) (*types.MsgRevokeSealResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Get the existing seal
	seal, err := k.Keeper.GetSeal(ctx, msg.SealId)
	if err != nil {
		return nil, fmt.Errorf("seal not found: %s", msg.SealId)
	}

	// Check if the authority is the seal creator or module authority
	if msg.Authority != seal.RequestedBy && msg.Authority != k.GetAuthority() {
		return nil, fmt.Errorf("unauthorized: only seal creator or module authority can revoke")
	}

	// Revoke the seal
	if err := k.Keeper.RevokeSeal(ctx, msg.SealId, msg.Reason); err != nil {
		return nil, err
	}

	return &types.MsgRevokeSealResponse{}, nil
}

package keeper_test

import (
	"bytes"
	"strings"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func testAddr(seed byte) string {
	return sdk.AccAddress(bytes.Repeat([]byte{seed}, 20)).String()
}

func TestMsgServerSubmitRegisterCancelCapabilityAndPCR0(t *testing.T) {
	k, ctx := newTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)
	wrapped := sdk.WrapSDKContext(ctx)

	modelHash := bytes.Repeat([]byte{0x01}, 32)
	registerResp, err := msgServer.RegisterModel(wrapped, &types.MsgRegisterModel{
		Owner:        testAddr(1),
		ModelHash:    modelHash,
		ModelId:      "credit-model",
		Name:         "Credit Model",
		Version:      "1.0.0",
		Architecture: "transformer",
	})
	require.NoError(t, err)
	require.Equal(t, modelHash, registerResp.ModelHash)

	// Reserved metadata keys should be rejected.
	_, err = msgServer.SubmitJob(wrapped, &types.MsgSubmitJob{
		Creator:   testAddr(2),
		ModelHash: modelHash,
		InputHash: bytes.Repeat([]byte{0x02}, 32),
		ProofType: types.ProofTypeTEE,
		Purpose:   "credit_scoring",
		Metadata: map[string]string{
			"scheduler.priority": "high",
		},
	})
	require.ErrorContains(t, err, "reserved prefix")

	// Cancel on unknown job should fail fast.
	_, err = msgServer.CancelJob(wrapped, &types.MsgCancelJob{
		Creator: testAddr(9),
		JobId:   "missing-job",
	})
	require.ErrorContains(t, err, "job not found")

	// Existing capability keeps current jobs and reputation when updating.
	require.NoError(t, k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(3),
		MaxConcurrentJobs: 5,
		CurrentJobs:       3,
		ReputationScore:   77,
		IsOnline:          true,
	}))

	_, err = msgServer.RegisterValidatorCapability(wrapped, &types.MsgRegisterValidatorCapability{
		Creator:           testAddr(3),
		TeePlatforms:      []string{"aws-nitro"},
		ZkmlSystems:       []string{"ezkl"},
		MaxConcurrentJobs: 10,
		IsOnline:          false,
	})
	require.NoError(t, err)

	capability, err := k.GetValidatorCapability(ctx, testAddr(3))
	require.NoError(t, err)
	require.EqualValues(t, 3, capability.CurrentJobs)
	require.EqualValues(t, 77, capability.ReputationScore)
	require.False(t, capability.IsOnline)

	_, err = msgServer.RegisterValidatorPCR0(wrapped, &types.MsgRegisterValidatorPCR0{
		Creator:          testAddr(3),
		ValidatorAddress: testAddr(9),
		Pcr0Hex:          strings.Repeat("ab", 32),
	})
	require.ErrorContains(t, err, "creator must match validator_address")

	validPCR0 := strings.Repeat("ab", 32)
	_, err = msgServer.RegisterValidatorPCR0(wrapped, &types.MsgRegisterValidatorPCR0{
		Creator:          testAddr(3),
		ValidatorAddress: testAddr(3),
		Pcr0Hex:          validPCR0,
	})
	require.NoError(t, err)

	storedPCR0, err := k.ValidatorPCR0Mappings.Get(ctx, testAddr(3))
	require.NoError(t, err)
	require.Equal(t, validPCR0, storedPCR0)
}

func TestQueryModelModuleStatusAndKeeperAccessors(t *testing.T) {
	k, ctx := newTestKeeper(t)
	queryServer := keeper.NewQueryServerImpl(k)
	wrapped := sdk.WrapSDKContext(ctx)

	modelHash := bytes.Repeat([]byte{0x10}, 32)
	require.NoError(t, k.RegisterModel(ctx, &types.RegisteredModel{
		ModelHash:    modelHash,
		ModelId:      "model-10",
		Name:         "Model10",
		Version:      "1.0",
		Architecture: "cnn",
		Owner:        testAddr(4),
	}))

	_, err := queryServer.Model(wrapped, nil)
	require.ErrorContains(t, err, "request cannot be nil")
	_, err = queryServer.Model(wrapped, &types.QueryModelRequest{})
	require.ErrorContains(t, err, "model_hash cannot be empty")
	_, err = queryServer.Model(wrapped, &types.QueryModelRequest{ModelHash: bytes.Repeat([]byte{0xFF}, 32)})
	require.ErrorContains(t, err, "model not found")

	modelResp, err := queryServer.Model(wrapped, &types.QueryModelRequest{ModelHash: modelHash})
	require.NoError(t, err)
	require.Equal(t, "model-10", modelResp.Model.ModelId)

	require.NoError(t, k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(6),
		MaxConcurrentJobs: 2,
		IsOnline:          true,
		ReputationScore:   80,
	}))
	require.NoError(t, k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(7),
		MaxConcurrentJobs: 2,
		IsOnline:          false,
		ReputationScore:   50,
	}))

	status, err := k.GetModuleStatus(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 0, status.JobCount)
	require.EqualValues(t, 0, status.PendingJobCount)
	require.EqualValues(t, 2, status.ValidatorCount)
	require.EqualValues(t, 1, status.OnlineValidatorCount)
	require.EqualValues(t, ctx.BlockHeight(), status.BlockHeight)

	// Cover lightweight keeper accessors.
	require.Nil(t, k.Metrics())
	require.Nil(t, k.AuditLogger())
	require.Equal(t, "", k.GetAuthority())
	total, online := k.CountValidators(ctx)
	require.Equal(t, 2, total)
	require.Equal(t, 1, online)
}

func TestQueryValidatorPCR0AndRegistryStatus(t *testing.T) {
	k, ctx := newTestKeeper(t)
	queryServer := keeper.NewQueryServerImpl(k)
	wrapped := sdk.WrapSDKContext(ctx)

	_, err := queryServer.ValidatorPCR0(wrapped, nil)
	require.ErrorContains(t, err, "request cannot be nil")
	_, err = queryServer.ValidatorPCR0(wrapped, &types.QueryValidatorPCR0Request{})
	require.ErrorContains(t, err, "validator_address cannot be empty")
	_, err = queryServer.ValidatorPCR0(wrapped, &types.QueryValidatorPCR0Request{ValidatorAddress: testAddr(1)})
	require.ErrorContains(t, err, "mapping not found")

	pcr0 := strings.Repeat("cd", 32)
	require.NoError(t, k.RegisterValidatorPCR0(ctx, testAddr(1), pcr0))

	pcr0Resp, err := queryServer.ValidatorPCR0(wrapped, &types.QueryValidatorPCR0Request{
		ValidatorAddress: testAddr(1),
	})
	require.NoError(t, err)
	require.Equal(t, testAddr(1), pcr0Resp.ValidatorAddress)
	require.Equal(t, pcr0, pcr0Resp.Pcr0Hex)

	_, err = queryServer.IsPCR0Registered(wrapped, nil)
	require.ErrorContains(t, err, "request cannot be nil")
	_, err = queryServer.IsPCR0Registered(wrapped, &types.QueryIsPCR0RegisteredRequest{})
	require.ErrorContains(t, err, "pcr0_hex cannot be empty")
	_, err = queryServer.IsPCR0Registered(wrapped, &types.QueryIsPCR0RegisteredRequest{Pcr0Hex: "bad"})
	require.ErrorContains(t, err, "invalid PCR0 hex length")

	registeredResp, err := queryServer.IsPCR0Registered(wrapped, &types.QueryIsPCR0RegisteredRequest{
		Pcr0Hex: strings.ToUpper(pcr0),
	})
	require.NoError(t, err)
	require.Equal(t, pcr0, registeredResp.Pcr0Hex)
	require.True(t, registeredResp.Registered)

	unregisteredPCR0 := strings.Repeat("ef", 32)
	unregisteredResp, err := queryServer.IsPCR0Registered(wrapped, &types.QueryIsPCR0RegisteredRequest{
		Pcr0Hex: unregisteredPCR0,
	})
	require.NoError(t, err)
	require.Equal(t, unregisteredPCR0, unregisteredResp.Pcr0Hex)
	require.False(t, unregisteredResp.Registered)
}

package keeper

import (
	"bytes"
	"testing"
	"time"

	"cosmossdk.io/log"
	storemetrics "cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/seal/types"
)

func createSealKeeperWithStore(t *testing.T) (Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-seal-test",
		Height:  100,
		Time:    time.Now().UTC(),
	}, false, log.NewNopLogger()).WithEventManager(sdk.NewEventManager())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)
	storeService := runtime.NewKVStoreService(storeKey)

	k := NewKeeper(cdc, storeService, "authority")
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	require.NoError(t, k.SealCount.Set(ctx, 0))
	return k, ctx
}

func makeTestSeal(seed byte, purpose string) *types.DigitalSeal {
	model := bytes.Repeat([]byte{seed}, 32)
	input := bytes.Repeat([]byte{seed + 1}, 32)
	output := bytes.Repeat([]byte{seed + 2}, 32)
	requester := sdk.AccAddress(bytes.Repeat([]byte{seed}, 20)).String()

	seal := types.NewDigitalSeal(model, input, output, 100, requester, purpose)
	seal.AddAttestation(&types.TEEAttestation{
		ValidatorAddress: "validator-1",
		Platform:         "aws-nitro",
		Quote:            []byte("quote"),
	})
	seal.SetZKProof(&types.ZKMLProof{ProofSystem: "ezkl"})
	seal.Activate()
	seal.RegulatoryInfo = &types.RegulatoryInfo{
		ComplianceFrameworks: []string{"GDPR", "SOC2"},
	}
	return seal
}

func TestMsgAndQueryServers(t *testing.T) {
	k, ctx := createSealKeeperWithStore(t)
	msgServer := NewMsgServerImpl(k)
	queryServer := NewQueryServerImpl(k)
	wrappedCtx := sdk.WrapSDKContext(ctx)

	msg := &types.MsgCreateSeal{
		Creator:          sdk.AccAddress(bytes.Repeat([]byte{0xAA}, 20)).String(),
		JobId:            "job-1",
		ModelCommitment:  bytes.Repeat([]byte{0x01}, 32),
		InputCommitment:  bytes.Repeat([]byte{0x02}, 32),
		OutputCommitment: bytes.Repeat([]byte{0x03}, 32),
		Purpose:          "credit_scoring",
		TeeAttestations: []*types.TEEAttestation{
			{
				ValidatorAddress: "validator-1",
				Platform:         "aws-nitro",
				Quote:            []byte("quote"),
			},
		},
	}

	createResp, err := msgServer.CreateSeal(wrappedCtx, msg)
	require.NoError(t, err)
	require.NotEmpty(t, createResp.SealId)

	_, err = queryServer.Seal(wrappedCtx, &types.QuerySealRequest{})
	require.ErrorContains(t, err, "seal_id is required")

	sealResp, err := queryServer.Seal(wrappedCtx, &types.QuerySealRequest{SealId: createResp.SealId})
	require.NoError(t, err)
	require.Equal(t, createResp.SealId, sealResp.Seal.Id)

	sealsResp, err := queryServer.Seals(wrappedCtx, &types.QuerySealsRequest{Limit: 0, Offset: -1})
	require.NoError(t, err)
	require.GreaterOrEqual(t, sealsResp.Total, uint64(1))
	require.NotEmpty(t, sealsResp.Seals)

	_, err = queryServer.SealsByModel(wrappedCtx, &types.QuerySealsByModelRequest{})
	require.ErrorContains(t, err, "model_hash is required")
	byModel, err := queryServer.SealsByModel(wrappedCtx, &types.QuerySealsByModelRequest{
		ModelHash: msg.ModelCommitment,
	})
	require.NoError(t, err)
	require.NotEmpty(t, byModel.Seals)

	_, err = queryServer.VerifySeal(wrappedCtx, &types.QueryVerifySealRequest{})
	require.ErrorContains(t, err, "seal_id is required")

	verifyExisting, err := queryServer.VerifySeal(wrappedCtx, &types.QueryVerifySealRequest{SealId: createResp.SealId})
	require.NoError(t, err)
	require.True(t, verifyExisting.Valid)
	require.Equal(t, "tee", verifyExisting.VerificationType)

	verifyMissing, err := queryServer.VerifySeal(wrappedCtx, &types.QueryVerifySealRequest{SealId: "does-not-exist"})
	require.NoError(t, err)
	require.False(t, verifyMissing.Valid)
	require.Equal(t, "not_found", verifyMissing.Status)

	paramsResp, err := queryServer.Params(wrappedCtx, &types.QueryParamsRequest{})
	require.NoError(t, err)
	require.NotNil(t, paramsResp.Params)

	// Unauthorized revoke should fail.
	_, err = msgServer.RevokeSeal(wrappedCtx, &types.MsgRevokeSeal{
		Authority: "random-user",
		SealId:    createResp.SealId,
		Reason:    "policy",
	})
	require.ErrorContains(t, err, "unauthorized")

	// Creator can revoke.
	_, err = msgServer.RevokeSeal(wrappedCtx, &types.MsgRevokeSeal{
		Authority: msg.Creator,
		SealId:    createResp.SealId,
		Reason:    "policy",
	})
	require.NoError(t, err)
}

func TestEventEmittersAndHelpers(t *testing.T) {
	_, ctx := createSealKeeperWithStore(t)
	seal := makeTestSeal(7, "risk_scoring")

	EmitSealCreated(ctx, seal)
	EmitSealVerified(ctx, seal.Id, true, "tee")
	EmitSealActivated(ctx, seal.Id, "validator-1")
	EmitSealRevoked(ctx, seal.Id, "authority", "policy")
	EmitSealExpired(ctx, seal.Id)
	EmitSealAccessed(ctx, seal.Id, "auditor", "audit")
	EmitSealExported(ctx, seal.Id, "auditor", "json")
	EmitConsensusReached(ctx, "job-1", seal.OutputCommitment, 5, 4)
	EmitVerificationFailed(ctx, "job-2", "mismatch", "validator-2")
	EmitModelRegistered(ctx, "model-1", seal.ModelCommitment, "owner")

	events := ctx.EventManager().Events()
	require.GreaterOrEqual(t, len(events), 10)
	require.Equal(t, EventTypeSealCreated, events[0].Type)
	require.Equal(t, "true", events[0].Attributes[len(events[0].Attributes)-2].Value)

	require.Len(t, truncateHex(bytes.Repeat([]byte{0xAB}, 32)), 16)
	require.Equal(t, "aabb", truncateHex([]byte{0xAA, 0xBB}))

	emitter := NewSealEventEmitter()
	called := 0
	emitter.RegisterHandler(func(event SealEvent) {
		called++
		require.Equal(t, "seal_created", event.Type)
	})
	emitter.notifyHandlers(SealEvent{Type: "seal_created"})
	require.Equal(t, 1, called)
}

func TestSealIndexQueryCoverage(t *testing.T) {
	idx := NewSealIndex()
	sealA := makeTestSeal(1, "credit_scoring")
	sealA.ValidatorSet = []string{"v1", "v2"}
	sealA.BlockHeight = 10
	sealB := makeTestSeal(2, "fraud_detection")
	sealB.ValidatorSet = []string{"v2"}
	sealB.BlockHeight = 12
	sealB.Status = types.SealStatusRevoked

	idx.IndexSeal(sealA)
	idx.IndexSeal(sealB)

	require.NotEmpty(t, idx.GetByModelHash(sealA.ModelCommitment))
	require.NotEmpty(t, idx.GetByPurpose("credit_scoring"))
	require.NotEmpty(t, idx.GetByRequester(sealA.RequestedBy))
	require.NotEmpty(t, idx.GetByStatus(types.SealStatusRevoked))
	require.NotEmpty(t, idx.GetByBlockHeight(10))
	require.Len(t, idx.GetByBlockHeightRange(10, 12), 2)
	require.NotEmpty(t, idx.GetByValidator("v2"))
	require.NotEmpty(t, idx.GetByComplianceFramework("GDPR"))

	idx.UpdateSealStatus(sealA.Id, types.SealStatusActive, types.SealStatusRevoked)
	require.NotContains(t, idx.GetByStatus(types.SealStatusActive), sealA.Id)
	require.Contains(t, idx.GetByStatus(types.SealStatusRevoked), sealA.Id)

	status := types.SealStatusRevoked
	require.NotEmpty(t, idx.ExecuteQuery(SealQuery{Status: &status}))
	require.NotEmpty(t, idx.ExecuteQuery(SealQuery{ModelHash: sealA.ModelCommitment, Limit: 1, Offset: 0}))
	require.NotEmpty(t, idx.ExecuteQuery(SealQuery{Requester: sealA.RequestedBy}))
	require.NotEmpty(t, idx.ExecuteQuery(SealQuery{Purpose: "fraud_detection"}))
	require.NotEmpty(t, idx.ExecuteQuery(SealQuery{Validator: "v1"}))
	require.NotEmpty(t, idx.ExecuteQuery(SealQuery{ComplianceFramework: "SOC2"}))
	require.NotEmpty(t, idx.ExecuteQuery(SealQuery{MinBlockHeight: 9, MaxBlockHeight: 12}))

	stats := idx.GetStats()
	require.Equal(t, 2, stats.TotalSeals)
	require.Equal(t, 2, stats.UniqueModels)
	require.Equal(t, 2, stats.UniquePurposes)
	require.Equal(t, 2, stats.UniqueRequesters)
	require.Equal(t, 2, stats.UniqueValidators)
	require.Equal(t, 2, stats.ComplianceFrameworks)
}

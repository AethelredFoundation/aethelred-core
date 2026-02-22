package keeper_test

import (
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

	"github.com/aethelred/aethelred/x/crisis/keeper"
	"github.com/aethelred/aethelred/x/crisis/types"
)

func setupKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Unix(1_770_100_000, 0).UTC(),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	k := keeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		"aeth1gov",
	)

	return k, ctx
}

func baseCouncil() types.SecurityCouncilConfig {
	return types.SecurityCouncilConfig{
		Threshold: types.SecurityCouncilThreshold,
		Members: []types.SecurityCouncilMember{
			{Address: "validator-1", Role: types.RoleValidator},
			{Address: "validator-2", Role: types.RoleValidator},
			{Address: "validator-3", Role: types.RoleValidator},
			{Address: "foundation-1", Role: types.RoleFoundation},
			{Address: "foundation-2", Role: types.RoleFoundation},
			{Address: "auditor-1", Role: types.RoleAuditor},
			{Address: "auditor-2", Role: types.RoleAuditor},
		},
	}
}

func TestMsgHaltNetwork_ValidFiveOfSeven(t *testing.T) {
	k, ctx := setupKeeper(t)
	require.NoError(t, k.SetSecurityCouncilConfig(ctx, "aeth1gov", baseCouncil()))

	err := k.MsgHaltNetwork(ctx, types.MsgHaltNetwork{
		Requester: "validator-1",
		Reason:    "zero-day in nitro attestation path",
		Signers: []string{
			"validator-1",
			"validator-2",
			"foundation-1",
			"auditor-1",
			"auditor-2",
		},
	})
	require.NoError(t, err)

	state, err := k.GetHaltState(ctx)
	require.NoError(t, err)
	require.True(t, state.Active)
	require.True(t, state.BridgeTransfersHalted)
	require.True(t, state.PoUWAllocationsHalted)
	require.True(t, state.GovernanceAllowed)
}

func TestMsgHaltNetwork_RejectsInsufficientSignatures(t *testing.T) {
	k, ctx := setupKeeper(t)
	require.NoError(t, k.SetSecurityCouncilConfig(ctx, "aeth1gov", baseCouncil()))

	err := k.MsgHaltNetwork(ctx, types.MsgHaltNetwork{
		Requester: "validator-1",
		Reason:    "critical bridge incident",
		Signers: []string{
			"validator-1",
			"foundation-1",
			"auditor-1",
			"auditor-2",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient signatures")
}

func TestMsgHaltNetwork_RejectsNonMemberSigner(t *testing.T) {
	k, ctx := setupKeeper(t)
	require.NoError(t, k.SetSecurityCouncilConfig(ctx, "aeth1gov", baseCouncil()))

	err := k.MsgHaltNetwork(ctx, types.MsgHaltNetwork{
		Requester: "validator-1",
		Reason:    "critical bridge incident",
		Signers: []string{
			"validator-1",
			"validator-2",
			"foundation-1",
			"auditor-1",
			"external-key",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a security council member")
}

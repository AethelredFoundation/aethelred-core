package app

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

	sovereigncrisiskeeper "github.com/aethelred/aethelred/x/crisis/keeper"
	sovereigncrisistypes "github.com/aethelred/aethelred/x/crisis/types"
)

func TestAssignedJobsForValidator_HaltedByCrisisReturnsNoAssignments(t *testing.T) {
	storeKey := storetypes.NewKVStoreKey(sovereigncrisistypes.StoreKey)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  50,
		Time:    time.Unix(1_770_200_000, 0).UTC(),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	crisisKeeper := sovereigncrisiskeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		"aeth1gov",
	)

	cfg := sovereigncrisistypes.SecurityCouncilConfig{
		Threshold: sovereigncrisistypes.SecurityCouncilThreshold,
		Members: []sovereigncrisistypes.SecurityCouncilMember{
			{Address: "validator-1", Role: sovereigncrisistypes.RoleValidator},
			{Address: "validator-2", Role: sovereigncrisistypes.RoleValidator},
			{Address: "validator-3", Role: sovereigncrisistypes.RoleValidator},
			{Address: "foundation-1", Role: sovereigncrisistypes.RoleFoundation},
			{Address: "foundation-2", Role: sovereigncrisistypes.RoleFoundation},
			{Address: "auditor-1", Role: sovereigncrisistypes.RoleAuditor},
			{Address: "auditor-2", Role: sovereigncrisistypes.RoleAuditor},
		},
	}
	require.NoError(t, crisisKeeper.SetSecurityCouncilConfig(ctx, "aeth1gov", cfg))
	require.NoError(t, crisisKeeper.MsgHaltNetwork(ctx, sovereigncrisistypes.MsgHaltNetwork{
		Requester: "validator-1",
		Reason:    "emergency response test",
		Signers: []string{
			"validator-1",
			"validator-2",
			"foundation-1",
			"auditor-1",
			"auditor-2",
		},
	}))

	app := &AethelredApp{
		SovereignCrisisKeeper: crisisKeeper,
	}

	jobs, validatorAddr, err := app.assignedJobsForValidator(ctx, []byte("consensus-addr"))
	require.NoError(t, err)
	require.Len(t, jobs, 0)
	require.Equal(t, "", validatorAddr)
}

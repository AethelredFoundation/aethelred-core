package seal_test

import (
	"testing"
	"time"

	"cosmossdk.io/core/store"
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

	"github.com/aethelred/aethelred/x/seal"
	"github.com/aethelred/aethelred/x/seal/keeper"
	"github.com/aethelred/aethelred/x/seal/types"
)

// setupAppModule creates a test AppModule with in-memory keeper
func setupAppModule(t *testing.T) (seal.AppModule, sdk.Context, codec.Codec) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  1,
		Time:    time.Now().UTC(),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	types.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)

	// Create keeper with store service
	k := keeper.NewKeeper(cdc, storeService, "authority")

	appModule := seal.NewAppModule(cdc, k)

	// Initialize params
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))

	return appModule, ctx, cdc
}

func TestAppModule_Lifecycle(t *testing.T) {
	am, ctx, cdc := setupAppModule(t)

	// 1. Export default genesis
	defaultGenesis := am.DefaultGenesis(cdc)
	require.NotNil(t, defaultGenesis)

	// 2. Validate default genesis
	err := am.ValidateGenesis(cdc, nil, defaultGenesis)
	require.NoError(t, err)

	// 3. InitGenesis with some state
	genesisState := types.DefaultGenesis()
	// Add a test seal
	testSeal := types.DigitalSeal{
		Id:          "seal-1",
		RequestedBy: "addr1",
		Status:      types.SealStatusActive,
		BlockHeight: 100,
	}
	genesisState.Seals = []*types.DigitalSeal{&testSeal}

	bz := cdc.MustMarshalJSON(genesisState)
	am.InitGenesis(ctx, cdc, bz)

	// 4. Verify state was imported (via ExportGenesis)
	exportedJSON := am.ExportGenesis(ctx, cdc)

	var exportedGenesis types.GenesisState
	err = cdc.UnmarshalJSON(exportedJSON, &exportedGenesis)
	require.NoError(t, err)

	require.Len(t, exportedGenesis.Seals, 1)
	require.Equal(t, "seal-1", exportedGenesis.Seals[0].Id)
}

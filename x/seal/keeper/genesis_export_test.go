package keeper_test

import (
	"crypto/sha256"
	"fmt"
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

	"github.com/aethelred/aethelred/x/seal/keeper"
	"github.com/aethelred/aethelred/x/seal/types"
)

func TestExportGenesis_NoTruncation(t *testing.T) {
	k, ctx := newSealTestKeeper(t)

	const total = 12050
	for i := 0; i < total; i++ {
		seal := makeExportTestSeal(i)
		require.NoError(t, k.SetSeal(ctx, seal))
	}
	require.NoError(t, k.SealCount.Set(ctx, uint64(total)))

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)
	require.Len(t, exported.Seals, total)

	ids := make(map[string]struct{}, total)
	for _, seal := range exported.Seals {
		ids[seal.Id] = struct{}{}
	}
	require.Len(t, ids, total)
}

func newSealTestKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  1,
		Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)
	storeService := runtime.NewKVStoreService(storeKey)

	k := keeper.NewKeeper(cdc, storeService, "aethelred")
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	require.NoError(t, k.SealCount.Set(ctx, 0))

	return k, ctx
}

func makeExportTestSeal(i int) *types.DigitalSeal {
	model := sha256.Sum256([]byte(fmt.Sprintf("model-%d", i)))
	input := sha256.Sum256([]byte(fmt.Sprintf("input-%d", i)))
	output := sha256.Sum256([]byte(fmt.Sprintf("output-%d", i)))

	seal := types.NewDigitalSeal(
		model[:],
		input[:],
		output[:],
		100+int64(i),
		testAccAddress(byte(i%250+1)),
		"export-test",
	)

	return seal
}

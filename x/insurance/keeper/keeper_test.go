package keeper_test

import (
	"context"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
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

	"github.com/aethelred/aethelred/x/insurance/keeper"
	"github.com/aethelred/aethelred/x/insurance/types"
)

type mockValidatorSource struct {
	validators []string
	slashed    map[string]bool
}

func (m mockValidatorSource) ListValidators(_ context.Context) ([]string, error) {
	out := make([]string, len(m.validators))
	copy(out, m.validators)
	return out, nil
}

func (m mockValidatorSource) IsValidatorSlashed(_ context.Context, validator string) bool {
	return m.slashed[validator]
}

func setupKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  1,
		Time:    time.Unix(1_770_000_000, 0).UTC(),
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

func TestInsuranceEscrowAppealReimbursesOnTribunalMajority(t *testing.T) {
	k, ctx := setupKeeper(t)
	k.SetValidatorSource(mockValidatorSource{
		validators: []string{
			"val-1",
			"val-2",
			"val-3",
			"val-4",
			"val-5",
			"val-6",
			"val-7",
			"val-8",
		},
		slashed: map[string]bool{
			"val-8": true,
		},
	})

	escrowID, err := k.EscrowFraudSlash(ctx, "val-1", sdkmath.NewInt(100_000), "fake_attestation", "tee-doc-hash")
	require.NoError(t, err)
	require.NotEmpty(t, escrowID)

	appeal, err := k.MsgSubmitAppeal(ctx, types.MsgSubmitAppeal{
		ValidatorAddress: "val-1",
		EscrowID:         escrowID,
		TeeLogURI:        "s3://tee-logs/failure-1",
		EvidenceHash:     "proof-hash",
	})
	require.NoError(t, err)
	require.Len(t, appeal.Tribunal, types.TribunalSize)
	require.NotContains(t, appeal.Tribunal, "val-1")
	require.NotContains(t, appeal.Tribunal, "val-8")

	for _, voter := range appeal.Tribunal[:types.TribunalMajority] {
		err = k.CastTribunalVote(ctx, appeal.ID, voter, true, "verified cloud hardware anomaly")
		require.NoError(t, err)
	}

	updatedAppeal, err := k.GetAppeal(ctx, appeal.ID)
	require.NoError(t, err)
	require.Equal(t, types.AppealStatusApproved, updatedAppeal.Status)

	updatedEscrow, err := k.GetEscrow(ctx, escrowID)
	require.NoError(t, err)
	require.Equal(t, types.EscrowStatusReimbursed, updatedEscrow.Status)
}

func TestInsuranceEscrowExpiresAfterFourteenDays(t *testing.T) {
	k, ctx := setupKeeper(t)
	k.SetValidatorSource(mockValidatorSource{
		validators: []string{"val-1", "val-2", "val-3", "val-4", "val-5", "val-6"},
		slashed:    map[string]bool{},
	})

	escrowID, err := k.EscrowFraudSlash(ctx, "val-1", sdkmath.NewInt(50_000), "invalid_output", "output-hash")
	require.NoError(t, err)

	expiryCtx := ctx.WithBlockTime(ctx.BlockTime().Add((types.EscrowDurationDays + 1) * 24 * time.Hour))
	expired, err := k.ProcessEscrowExpiries(expiryCtx)
	require.NoError(t, err)
	require.Equal(t, 1, expired)

	record, err := k.GetEscrow(expiryCtx, escrowID)
	require.NoError(t, err)
	require.Equal(t, types.EscrowStatusForfeited, record.Status)
}

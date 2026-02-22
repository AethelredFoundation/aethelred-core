package keeper_test

import (
	"bytes"
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
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
)

type feeDistMockStakingKeeper struct {
	validators []stakingtypes.Validator
}

func (m feeDistMockStakingKeeper) GetAllValidators(_ context.Context) ([]stakingtypes.Validator, error) {
	return m.validators, nil
}

func (m feeDistMockStakingKeeper) GetValidator(_ context.Context, _ sdk.ValAddress) (stakingtypes.Validator, error) {
	if len(m.validators) == 0 {
		return stakingtypes.Validator{}, nil
	}
	return m.validators[0], nil
}

type feeDistMockBankKeeper struct{}

func (m feeDistMockBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, _ sdk.AccAddress, _ sdk.Coins) error {
	return nil
}

func (m feeDistMockBankKeeper) SendCoinsFromAccountToModule(_ context.Context, _ sdk.AccAddress, _ string, _ sdk.Coins) error {
	return nil
}

func (m feeDistMockBankKeeper) SendCoinsFromModuleToModule(_ context.Context, _, _ string, _ sdk.Coins) error {
	return nil
}

func (m feeDistMockBankKeeper) BurnCoins(_ context.Context, _ string, _ sdk.Coins) error {
	return nil
}

func (m feeDistMockBankKeeper) SpendableCoins(_ context.Context, _ sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}

type moduleTransfer struct {
	from   string
	to     string
	amount sdk.Coins
}

type trackingFeeDistBankKeeper struct {
	moduleToModule []moduleTransfer
}

func (m *trackingFeeDistBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, _ sdk.AccAddress, _ sdk.Coins) error {
	return nil
}

func (m *trackingFeeDistBankKeeper) SendCoinsFromAccountToModule(_ context.Context, _ sdk.AccAddress, _ string, _ sdk.Coins) error {
	return nil
}

func (m *trackingFeeDistBankKeeper) SendCoinsFromModuleToModule(_ context.Context, senderModule, recipientModule string, amt sdk.Coins) error {
	m.moduleToModule = append(m.moduleToModule, moduleTransfer{
		from:   senderModule,
		to:     recipientModule,
		amount: amt,
	})
	return nil
}

func (m *trackingFeeDistBankKeeper) BurnCoins(_ context.Context, _ string, _ sdk.Coins) error {
	return nil
}

func (m *trackingFeeDistBankKeeper) SpendableCoins(_ context.Context, _ sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}

func newFeeDistKeeper(t *testing.T, validators []stakingtypes.Validator) (keeper.Keeper, sdk.Context) {
	return newFeeDistKeeperWithBank(t, validators, feeDistMockBankKeeper{})
}

func newFeeDistKeeperWithBank(t *testing.T, validators []stakingtypes.Validator, bank keeper.BankKeeper) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-fee-test",
		Height:  1,
		Time:    time.Unix(1_700_000_000, 0).UTC(),
	}, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)
	storeService := runtime.NewKVStoreService(storeKey)

	k := keeper.NewKeeper(
		cdc,
		storeService,
		feeDistMockStakingKeeper{validators: validators},
		bank,
		sealkeeper.Keeper{},
		verifykeeper.Keeper{},
		"gov",
	)

	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	require.NoError(t, k.JobCount.Set(ctx, 0))
	return k, ctx
}

func TestComputeEmissionSchedule_HighGrowth_NoOverflowArtifacts(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.InitialInflationBps = 2000
	config.TargetInflationBps = 2000
	config.DecayModel = keeper.EmissionLinearDecay
	config.DecayPeriodYears = 20

	schedule := keeper.ComputeEmissionSchedule(config, 250)
	require.NotEmpty(t, schedule)
	require.LessOrEqual(t, len(schedule), 250)

	for i, entry := range schedule {
		require.GreaterOrEqual(t, entry.AnnualEmission, int64(0), "year=%d", i+1)
		require.GreaterOrEqual(t, entry.CumulativeSupply, int64(0), "year=%d", i+1)
		if i > 0 {
			require.GreaterOrEqual(
				t,
				entry.CumulativeSupply,
				schedule[i-1].CumulativeSupply,
				"cumulative supply must be non-decreasing at year=%d",
				i+1,
			)
		}
	}
}

func TestBondingCurve_RejectsUnsupportedExponent(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	config.ExponentScaled = 1300

	require.Error(t, keeper.ValidateBondingCurveConfig(config))

	curve := keeper.NewBondingCurve(config)
	_, err := curve.CalculatePurchaseCost(sdkmath.NewInt(1_000_000))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported bonding curve exponent")
}

func TestBondingCurve_GetCurrentPriceSafe_RejectsUnsupportedExponent(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	config.ExponentScaled = 1300

	curve := keeper.NewBondingCurve(config)
	_, err := curve.GetCurrentPriceSafe()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported bonding curve exponent")
	require.True(t, curve.GetCurrentPrice().IsZero(), "invalid config must fail closed")
}

func TestEstimateAnnualValidatorRevenue_UsesActiveValidatorCount(t *testing.T) {
	validators := []stakingtypes.Validator{
		{Status: stakingtypes.Bonded, Jailed: false},
		{Status: stakingtypes.Bonded, Jailed: false},
		{Status: stakingtypes.Bonded, Jailed: false},
		{Status: stakingtypes.Bonded, Jailed: false},
		{Status: stakingtypes.Bonded, Jailed: false},
	}

	k, ctx := newFeeDistKeeper(t, validators)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	estimate, err := fd.EstimateAnnualValidatorRevenue(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(5), estimate.ActiveValidators)

	expectedPerValidator := estimate.ValidatorShare.Amount.QuoRaw(5)
	require.True(t, estimate.PerValidatorAnnual.Amount.Equal(expectedPerValidator))
}

func TestFeeDistributor_PersistsTreasuryAndInsuranceEarmarks(t *testing.T) {
	validators := []stakingtypes.Validator{
		{Status: stakingtypes.Bonded, Jailed: false},
		{Status: stakingtypes.Bonded, Jailed: false},
	}
	k, ctx := newFeeDistKeeper(t, validators)
	config := keeper.DefaultFeeDistributionConfig()
	fd := keeper.NewFeeDistributor(&k, config)

	val1 := sdk.AccAddress(bytes.Repeat([]byte{0x01}, 20)).String()
	val2 := sdk.AccAddress(bytes.Repeat([]byte{0x02}, 20)).String()
	validatorAddrs := []string{val1, val2}

	fee := sdk.NewInt64Coin("uaeth", 1_000_000)
	expectedSingle := keeper.CalculateFeeBreakdown(fee, config, len(validatorAddrs))

	_, err := fd.DistributeJobFee(ctx, fee, validatorAddrs)
	require.NoError(t, err)
	_, err = fd.DistributeJobFee(ctx, fee, validatorAddrs)
	require.NoError(t, err)

	treasury, err := k.GetTreasuryEarmarkedBalance(ctx, fee.Denom)
	require.NoError(t, err)
	insurance, err := k.GetInsuranceFundEarmarkedBalance(ctx, fee.Denom)
	require.NoError(t, err)

	require.True(t, treasury.Amount.Equal(expectedSingle.TreasuryAmount.Amount.MulRaw(2)))
	require.True(t, insurance.Amount.Equal(expectedSingle.InsuranceFund.Amount.MulRaw(2)))
}

func TestFeeDistributor_UsesDedicatedTreasuryAndInsuranceModuleAccounts(t *testing.T) {
	validators := []stakingtypes.Validator{
		{Status: stakingtypes.Bonded, Jailed: false},
		{Status: stakingtypes.Bonded, Jailed: false},
	}
	bank := &trackingFeeDistBankKeeper{}
	k, ctx := newFeeDistKeeperWithBank(t, validators, bank)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	val1 := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20)).String()
	val2 := sdk.AccAddress(bytes.Repeat([]byte{0x12}, 20)).String()
	validatorAddrs := []string{val1, val2}

	fee := sdk.NewInt64Coin("uaeth", 1_000_000)
	expected := keeper.CalculateFeeBreakdown(fee, keeper.DefaultFeeDistributionConfig(), len(validatorAddrs))

	_, err := fd.DistributeJobFee(ctx, fee, validatorAddrs)
	require.NoError(t, err)
	require.Len(t, bank.moduleToModule, 2)

	require.Equal(t, types.ModuleName, bank.moduleToModule[0].from)
	require.Equal(t, types.TreasuryModuleName, bank.moduleToModule[0].to)
	require.Equal(t, sdk.NewCoins(expected.TreasuryAmount), bank.moduleToModule[0].amount)

	require.Equal(t, types.ModuleName, bank.moduleToModule[1].from)
	require.Equal(t, types.InsuranceModuleName, bank.moduleToModule[1].to)
	require.Equal(t, sdk.NewCoins(expected.InsuranceFund), bank.moduleToModule[1].amount)
}

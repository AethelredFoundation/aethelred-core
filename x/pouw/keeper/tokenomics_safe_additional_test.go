package keeper

import (
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestSafeMathCoreOperations(t *testing.T) {
	sm := NewSafeMath()

	sum, err := sm.SafeAdd(sdkmath.NewInt(10), sdkmath.NewInt(20))
	require.NoError(t, err)
	require.EqualValues(t, 30, sum.Int64())

	diff, err := sm.SafeSub(sdkmath.NewInt(20), sdkmath.NewInt(7))
	require.NoError(t, err)
	require.EqualValues(t, 13, diff.Int64())

	product, err := sm.SafeMul(sdkmath.NewInt(12), sdkmath.NewInt(11))
	require.NoError(t, err)
	require.EqualValues(t, 132, product.Int64())

	quotient, err := sm.SafeDiv(sdkmath.NewInt(100), sdkmath.NewInt(4))
	require.NoError(t, err)
	require.EqualValues(t, 25, quotient.Int64())

	_, err = sm.SafeDiv(sdkmath.NewInt(1), sdkmath.ZeroInt())
	require.ErrorContains(t, err, "division by zero")

	mulDiv, err := sm.SafeMulDiv(sdkmath.NewInt(1000), sdkmath.NewInt(500), sdkmath.NewInt(BpsBase))
	require.NoError(t, err)
	require.EqualValues(t, 50, mulDiv.Int64())

	bpsValue, err := sm.SafeBpsMultiply(sdkmath.NewInt(1000), 2500)
	require.NoError(t, err)
	require.EqualValues(t, 250, bpsValue.Int64())
}

func TestBondingCurveValidationAndStateTransitions(t *testing.T) {
	validCfg := DefaultBondingCurveConfig()
	require.NoError(t, ValidateBondingCurveConfig(validCfg))
	require.Equal(t, []int64{1000, 1500, 2000}, SupportedBondingCurveExponents())

	invalid := validCfg
	invalid.ExponentScaled = 1300
	require.Error(t, ValidateBondingCurveConfig(invalid))

	invalid = validCfg
	invalid.ReserveRatioBps = BpsBase + 1
	require.Error(t, ValidateBondingCurveConfig(invalid))

	curve := NewBondingCurve(validCfg)

	initialPrice, err := curve.GetCurrentPriceSafe()
	require.NoError(t, err)
	require.True(t, initialPrice.GT(sdkmath.ZeroInt()))

	tokenAmount := sdkmath.NewInt(100)
	cost, err := curve.CalculatePurchaseCost(tokenAmount)
	require.NoError(t, err)
	require.True(t, cost.GTE(sdkmath.ZeroInt()))

	executedCost, err := curve.ExecutePurchase(tokenAmount)
	require.NoError(t, err)
	require.True(t, executedCost.GTE(cost))

	supply, reserve, price := curve.GetState()
	require.True(t, supply.Equal(tokenAmount))
	require.True(t, reserve.GTE(sdkmath.ZeroInt()))
	require.True(t, price.GTE(sdkmath.ZeroInt()))

	saleReturn, err := curve.CalculateSaleReturn(sdkmath.NewInt(10))
	require.NoError(t, err)
	require.True(t, saleReturn.GTE(sdkmath.ZeroInt()))

	executedReturn, err := curve.ExecuteSale(sdkmath.NewInt(10))
	require.NoError(t, err)
	require.True(t, executedReturn.GTE(sdkmath.ZeroInt()))

	_, err = curve.CalculateSaleReturn(sdkmath.NewInt(1000))
	require.ErrorContains(t, err, "cannot sell more than current supply")

	disabledCfg := validCfg
	disabledCfg.Enabled = false
	disabledCurve := NewBondingCurve(disabledCfg)
	_, err = disabledCurve.CalculatePurchaseCost(sdkmath.NewInt(1))
	require.ErrorContains(t, err, "disabled")

	unsupportedCfg := validCfg
	unsupportedCfg.ExponentScaled = 1700
	unsupportedCurve := NewBondingCurve(unsupportedCfg)
	_, err = unsupportedCurve.GetCurrentPriceSafe()
	require.Error(t, err)
	_, err = unsupportedCurve.CalculatePurchaseCost(sdkmath.NewInt(1))
	require.Error(t, err)
}

func TestBlockTimeAndEmissionSafeCalculations(t *testing.T) {
	cfg := DefaultBlockTimeConfig()
	require.NoError(t, ValidateBlockTimeConfig(cfg))

	bad := cfg
	bad.TargetBlockTimeMs = 100
	require.Error(t, ValidateBlockTimeConfig(bad))

	bad = cfg
	bad.MaxBlockTimeMs = 61000
	require.Error(t, ValidateBlockTimeConfig(bad))

	bad = cfg
	bad.AdaptiveWindowBlocks = 5
	require.Error(t, ValidateBlockTimeConfig(bad))

	require.Greater(t, BlocksPerYearForConfig(cfg), int64(0))
	require.Greater(t, BlocksPerDayForConfig(cfg), int64(0))

	zeroTarget := cfg
	zeroTarget.TargetBlockTimeMs = 0
	require.Greater(t, BlocksPerYearForConfig(zeroTarget), int64(0))
	require.Greater(t, BlocksPerDayForConfig(zeroTarget), int64(0))

	model := DefaultTokenomicsModel()
	recalc := RecalculateTokenomicsForBlockTime(model, 3000)
	require.NotEqual(t, model.Staking.UnbondingPeriodBlocks, recalc.Staking.UnbondingPeriodBlocks)
	require.NotEqual(t, model.Slashing.DowntimeWindowBlocks, recalc.Slashing.DowntimeWindowBlocks)

	emissionCfg := DefaultEmissionConfig()
	schedule, err := ComputeEmissionScheduleSafe(emissionCfg, 3, cfg)
	require.NoError(t, err)
	require.Len(t, schedule, 3)
	require.True(t, schedule[0].AnnualEmission > 0)
	require.True(t, schedule[1].CumulativeSupply >= schedule[0].CumulativeSupply)
}

func TestComputeValidatorRewardSafe(t *testing.T) {
	base := sdk.NewInt64Coin("uaeth", 1_000_000)
	validatorReward, delegatorReward, err := ComputeValidatorRewardSafe(base, 80, 1000) // 10% commission
	require.NoError(t, err)
	require.Equal(t, base.Denom, validatorReward.Denom)
	require.Equal(t, base.Denom, delegatorReward.Denom)
	require.True(t, validatorReward.Amount.GT(sdkmath.ZeroInt()))
	require.True(t, delegatorReward.Amount.GT(sdkmath.ZeroInt()))
}

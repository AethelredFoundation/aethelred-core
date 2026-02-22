package keeper_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

type slashingBankKeeper struct {
	spendable sdk.Coins
	sendErr   error
	burnErr   error

	accountToModuleCalls int
	burnCalls            int
}

func (m *slashingBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, _ sdk.AccAddress, _ sdk.Coins) error {
	return nil
}

func (m *slashingBankKeeper) SendCoinsFromAccountToModule(_ context.Context, _ sdk.AccAddress, _ string, _ sdk.Coins) error {
	m.accountToModuleCalls++
	return m.sendErr
}

func (m *slashingBankKeeper) SendCoinsFromModuleToModule(_ context.Context, _, _ string, _ sdk.Coins) error {
	return nil
}

func (m *slashingBankKeeper) BurnCoins(_ context.Context, _ string, _ sdk.Coins) error {
	m.burnCalls++
	return m.burnErr
}

func (m *slashingBankKeeper) SpendableCoins(_ context.Context, _ sdk.AccAddress) sdk.Coins {
	return m.spendable
}

func sampleValAddr() string {
	return sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20)).String()
}

func TestEvidenceCollectorApplySlashingPenalties_SuccessAndErrors(t *testing.T) {
	t.Run("success path applies send and burn", func(t *testing.T) {
		bank := &slashingBankKeeper{
			spendable: sdk.NewCoins(sdk.NewInt64Coin("uaeth", 1_000_000_000)),
		}
		k, ctx := newFeeDistKeeperWithBank(t, nil, bank)
		ec := keeper.NewEvidenceCollector(log.NewNopLogger(), &k)

		records := []keeper.SlashingEvidenceRecord{
			{
				ValidatorAddress: sampleValAddr(),
				Condition:        "invalid_output",
				Severity:         "high",
				JobID:            "job-success",
				BlockHeight:      ctx.BlockHeight(),
				DetectedBy:       "test",
			},
		}

		errs := ec.ApplySlashingPenalties(ctx, records)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])
		require.True(t, records[0].Processed)
		require.Equal(t, 1, bank.accountToModuleCalls)
		require.Equal(t, 1, bank.burnCalls)
	})

	t.Run("invalid bech32 address is rejected", func(t *testing.T) {
		bank := &slashingBankKeeper{
			spendable: sdk.NewCoins(sdk.NewInt64Coin("uaeth", 1_000_000_000)),
		}
		k, ctx := newFeeDistKeeperWithBank(t, nil, bank)
		ec := keeper.NewEvidenceCollector(log.NewNopLogger(), &k)

		records := []keeper.SlashingEvidenceRecord{
			{
				ValidatorAddress: "not-a-valid-bech32",
				Condition:        "double_sign",
				Severity:         "critical",
				JobID:            "job-invalid-addr",
				BlockHeight:      ctx.BlockHeight(),
				DetectedBy:       "test",
			},
		}

		errs := ec.ApplySlashingPenalties(ctx, records)
		require.Error(t, errs[0])
		require.Contains(t, errs[0].Error(), "invalid validator address")
		require.False(t, records[0].Processed)
		require.Equal(t, 0, bank.accountToModuleCalls)
		require.Equal(t, 0, bank.burnCalls)
	})

	t.Run("insufficient funds", func(t *testing.T) {
		bank := &slashingBankKeeper{
			spendable: sdk.NewCoins(),
		}
		k, ctx := newFeeDistKeeperWithBank(t, nil, bank)
		ec := keeper.NewEvidenceCollector(log.NewNopLogger(), &k)

		records := []keeper.SlashingEvidenceRecord{
			{
				ValidatorAddress: sampleValAddr(),
				Condition:        "downtime",
				Severity:         "medium",
				JobID:            "job-insufficient",
				BlockHeight:      ctx.BlockHeight(),
				DetectedBy:       "test",
			},
		}

		errs := ec.ApplySlashingPenalties(ctx, records)
		require.Error(t, errs[0])
		require.Contains(t, errs[0].Error(), "insufficient funds")
		require.False(t, records[0].Processed)
		require.Equal(t, 0, bank.accountToModuleCalls)
		require.Equal(t, 0, bank.burnCalls)
	})

	t.Run("send failure", func(t *testing.T) {
		bank := &slashingBankKeeper{
			spendable: sdk.NewCoins(sdk.NewInt64Coin("uaeth", 1_000_000_000)),
			sendErr:   errors.New("send failed"),
		}
		k, ctx := newFeeDistKeeperWithBank(t, nil, bank)
		ec := keeper.NewEvidenceCollector(log.NewNopLogger(), &k)

		records := []keeper.SlashingEvidenceRecord{
			{
				ValidatorAddress: sampleValAddr(),
				Condition:        "invalid_output",
				Severity:         "high",
				JobID:            "job-send-fail",
				BlockHeight:      ctx.BlockHeight(),
				DetectedBy:       "test",
			},
		}

		errs := ec.ApplySlashingPenalties(ctx, records)
		require.Error(t, errs[0])
		require.Contains(t, errs[0].Error(), "failed to collect penalty")
		require.False(t, records[0].Processed)
		require.Equal(t, 1, bank.accountToModuleCalls)
		require.Equal(t, 0, bank.burnCalls)
	})

	t.Run("burn failure", func(t *testing.T) {
		bank := &slashingBankKeeper{
			spendable: sdk.NewCoins(sdk.NewInt64Coin("uaeth", 1_000_000_000)),
			burnErr:   errors.New("burn failed"),
		}
		k, ctx := newFeeDistKeeperWithBank(t, nil, bank)
		ec := keeper.NewEvidenceCollector(log.NewNopLogger(), &k)

		records := []keeper.SlashingEvidenceRecord{
			{
				ValidatorAddress: sampleValAddr(),
				Condition:        "invalid_output",
				Severity:         "high",
				JobID:            "job-burn-fail",
				BlockHeight:      ctx.BlockHeight(),
				DetectedBy:       "test",
			},
		}

		errs := ec.ApplySlashingPenalties(ctx, records)
		require.Error(t, errs[0])
		require.Contains(t, errs[0].Error(), "failed to burn penalty tokens")
		require.False(t, records[0].Processed)
		require.Equal(t, 1, bank.accountToModuleCalls)
		require.Equal(t, 1, bank.burnCalls)
	})
}

func TestEvidenceCollectorApplySlashingPenalties_InvalidParamFallback(t *testing.T) {
	bank := &slashingBankKeeper{
		spendable: sdk.NewCoins(sdk.NewInt64Coin("uaeth", 1_000_000_000)),
	}
	k, ctx := newFeeDistKeeperWithBank(t, nil, bank)
	params := types.DefaultParams()
	params.SlashingPenalty = "not-a-coin"
	require.NoError(t, k.SetParams(ctx, params))

	ec := keeper.NewEvidenceCollector(log.NewNopLogger(), &k)
	records := []keeper.SlashingEvidenceRecord{
		{
			ValidatorAddress: sampleValAddr(),
			Condition:        "double_sign",
			Severity:         "critical",
			JobID:            "job-fallback",
			BlockHeight:      ctx.BlockHeight(),
			DetectedBy:       "test",
		},
	}

	errs := ec.ApplySlashingPenalties(ctx, records)
	require.NoError(t, errs[0])
	require.True(t, records[0].Processed)
	require.Equal(t, 1, bank.accountToModuleCalls)
	require.Equal(t, 1, bank.burnCalls)
}


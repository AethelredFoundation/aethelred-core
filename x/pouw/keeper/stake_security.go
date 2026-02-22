package keeper

import (
	"context"
	"fmt"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

const (
	// BaseUnitsPerAETHEL is the denomination conversion factor.
	// 1 AETHEL = 1,000,000 uaeth.
	BaseUnitsPerAETHEL int64 = 1_000_000

	// AprilTestnetMinValidatorStakeAETHEL is the hardcoded minimum stake
	// required for active PoUW validator participation on the April 1 testnet.
	AprilTestnetMinValidatorStakeAETHEL int64 = 100_000
)

// MinimumValidatorStakeUAETH returns the hardcoded minimum bonded stake in uaeth.
func MinimumValidatorStakeUAETH() sdkmath.Int {
	return sdkmath.NewInt(AprilTestnetMinValidatorStakeAETHEL * BaseUnitsPerAETHEL)
}

// hasMinimumValidatorStake checks whether a validator maintains the minimum
// bonded stake required for active participation in PoUW.
//
// When no staking keeper is configured (unit-test environments), this returns
// true to preserve isolated keeper tests.
func (k Keeper) hasMinimumValidatorStake(ctx context.Context, validatorAddr string) bool {
	if k.stakingKeeper == nil {
		return true
	}

	stake, found := k.getValidatorBondedStake(ctx, validatorAddr)
	if !found {
		return false
	}

	return stake.GTE(MinimumValidatorStakeUAETH())
}

// getValidatorBondedStake resolves a validator address to staking state and
// returns its bonded stake in uaeth.
func (k Keeper) getValidatorBondedStake(ctx context.Context, validatorAddr string) (sdkmath.Int, bool) {
	if k.stakingKeeper == nil || validatorAddr == "" {
		return sdkmath.ZeroInt(), false
	}

	for _, valAddr := range resolveValidatorAddresses(validatorAddr) {
		validator, err := k.stakingKeeper.GetValidator(ctx, valAddr)
		if err != nil {
			continue
		}
		if validator.GetStatus() != stakingtypes.Bonded {
			continue
		}
		return validator.GetBondedTokens(), true
	}

	return sdkmath.ZeroInt(), false
}

func resolveValidatorAddresses(validatorAddr string) []sdk.ValAddress {
	var out []sdk.ValAddress
	seen := make(map[string]struct{})

	if valAddr, err := sdk.ValAddressFromBech32(validatorAddr); err == nil {
		key := valAddr.String()
		seen[key] = struct{}{}
		out = append(out, valAddr)
	}

	if accAddr, err := sdk.AccAddressFromBech32(validatorAddr); err == nil {
		valAddr := sdk.ValAddress(accAddr)
		key := valAddr.String()
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, valAddr)
		}
	}

	return out
}

type stakingSlashKeeper interface {
	Slash(ctx context.Context, consAddr sdk.ConsAddress, infractionHeight, power int64, slashFactor sdkmath.LegacyDec) (sdkmath.Int, error)
}

type stakingPowerKeeper interface {
	GetLastValidatorPower(ctx context.Context, operator sdk.ValAddress) (int64, error)
}

// slashValidatorBondedStake attempts to apply a slash directly against bonded
// stake. It returns (amount, true, nil) on success.
func (k Keeper) slashValidatorBondedStake(
	ctx context.Context,
	validatorAddr string,
	slashFactor sdkmath.LegacyDec,
) (sdkmath.Int, bool, error) {
	if k.stakingKeeper == nil {
		return sdkmath.ZeroInt(), false, nil
	}

	slasher, ok := k.stakingKeeper.(stakingSlashKeeper)
	if !ok {
		return sdkmath.ZeroInt(), false, nil
	}

	for _, valAddr := range resolveValidatorAddresses(validatorAddr) {
		validator, err := k.stakingKeeper.GetValidator(ctx, valAddr)
		if err != nil {
			continue
		}
		if validator.GetStatus() != stakingtypes.Bonded {
			continue
		}

		consAddrBz, err := validator.GetConsAddr()
		if err != nil {
			return sdkmath.ZeroInt(), false, fmt.Errorf("failed to derive consensus address: %w", err)
		}

		power := validator.GetConsensusPower(sdk.DefaultPowerReduction)
		if powerKeeper, hasPowerKeeper := k.stakingKeeper.(stakingPowerKeeper); hasPowerKeeper {
			if historicalPower, powerErr := powerKeeper.GetLastValidatorPower(ctx, valAddr); powerErr == nil && historicalPower > 0 {
				power = historicalPower
			}
		}
		if power <= 0 {
			return sdkmath.ZeroInt(), false, fmt.Errorf("validator power is zero")
		}

		sdkCtx := sdk.UnwrapSDKContext(ctx)
		amount, slashErr := slasher.Slash(
			ctx,
			sdk.ConsAddress(consAddrBz),
			sdkCtx.BlockHeight(),
			power,
			slashFactor,
		)
		if slashErr != nil {
			return sdkmath.ZeroInt(), false, slashErr
		}

		return amount, true, nil
	}

	return sdkmath.ZeroInt(), false, nil
}

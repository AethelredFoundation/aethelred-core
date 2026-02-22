package keeper

import (
	"fmt"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// RecordTreasuryEarmark increments the on-chain treasury earmark balance.
func (k Keeper) RecordTreasuryEarmark(ctx sdk.Context, amount sdk.Coin) error {
	return k.addEarmarkAmount(ctx, types.TreasuryEarmarkKeyPrefix, amount)
}

// RecordInsuranceFundEarmark increments the on-chain insurance earmark balance.
func (k Keeper) RecordInsuranceFundEarmark(ctx sdk.Context, amount sdk.Coin) error {
	return k.addEarmarkAmount(ctx, types.InsuranceEarmarkKeyPrefix, amount)
}

// GetTreasuryEarmarkedBalance returns the tracked treasury earmark for denom.
func (k Keeper) GetTreasuryEarmarkedBalance(ctx sdk.Context, denom string) (sdk.Coin, error) {
	amount, err := k.getEarmarkAmount(ctx, types.TreasuryEarmarkKeyPrefix, denom)
	if err != nil {
		return sdk.Coin{}, err
	}
	return sdk.NewCoin(denom, amount), nil
}

// GetInsuranceFundEarmarkedBalance returns the tracked insurance earmark for denom.
func (k Keeper) GetInsuranceFundEarmarkedBalance(ctx sdk.Context, denom string) (sdk.Coin, error) {
	amount, err := k.getEarmarkAmount(ctx, types.InsuranceEarmarkKeyPrefix, denom)
	if err != nil {
		return sdk.Coin{}, err
	}
	return sdk.NewCoin(denom, amount), nil
}

func (k Keeper) addEarmarkAmount(ctx sdk.Context, prefix []byte, amount sdk.Coin) error {
	if !amount.IsPositive() {
		return nil
	}
	if k.storeService == nil {
		return fmt.Errorf("store service not configured")
	}
	if amount.Denom == "" {
		return fmt.Errorf("denom must not be empty")
	}

	current, err := k.getEarmarkAmount(ctx, prefix, amount.Denom)
	if err != nil {
		return err
	}
	next := current.Add(amount.Amount)

	store := k.storeService.OpenKVStore(ctx)
	return store.Set(earmarkKey(prefix, amount.Denom), []byte(next.String()))
}

func (k Keeper) getEarmarkAmount(ctx sdk.Context, prefix []byte, denom string) (sdkmath.Int, error) {
	if k.storeService == nil {
		return sdkmath.ZeroInt(), fmt.Errorf("store service not configured")
	}
	if denom == "" {
		return sdkmath.ZeroInt(), fmt.Errorf("denom must not be empty")
	}

	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(earmarkKey(prefix, denom))
	if err != nil {
		return sdkmath.ZeroInt(), err
	}
	if len(bz) == 0 {
		return sdkmath.ZeroInt(), nil
	}

	value, ok := sdkmath.NewIntFromString(string(bz))
	if !ok {
		return sdkmath.ZeroInt(), fmt.Errorf("invalid earmark amount for denom %s", denom)
	}
	return value, nil
}

func earmarkKey(prefix []byte, denom string) []byte {
	key := append([]byte{}, prefix...)
	return append(key, []byte(denom)...)
}

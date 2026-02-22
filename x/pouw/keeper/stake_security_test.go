package keeper_test

import (
	"testing"

	sdkmath "cosmossdk.io/math"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestRegisterValidatorCapability_RejectsBelowMinimumBondedStake(t *testing.T) {
	minStake := keeper.MinimumValidatorStakeUAETH()
	validator := stakingtypes.Validator{
		Status: stakingtypes.Bonded,
		Tokens: minStake.Sub(sdkmath.NewInt(1)),
	}

	k, ctx := newFeeDistKeeper(t, []stakingtypes.Validator{validator})

	err := k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(5),
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 2,
		IsOnline:          true,
		ReputationScore:   70,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "minimum bonded stake requirement")
}

func TestRegisterValidatorCapability_AllowsAtOrAboveMinimumBondedStake(t *testing.T) {
	minStake := keeper.MinimumValidatorStakeUAETH()
	validator := stakingtypes.Validator{
		Status: stakingtypes.Bonded,
		Tokens: minStake,
	}

	k, ctx := newFeeDistKeeper(t, []stakingtypes.Validator{validator})

	err := k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(6),
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 2,
		IsOnline:          true,
		ReputationScore:   70,
	})
	require.NoError(t, err)
}

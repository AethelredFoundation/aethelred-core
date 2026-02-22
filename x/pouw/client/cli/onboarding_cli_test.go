package cli

import (
	"testing"

	sdkmath "cosmossdk.io/math"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestParseStakeAmount(t *testing.T) {
	t.Run("converts aethel display denom to base denom", func(t *testing.T) {
		coin, err := parseStakeAmount("100000aethel")
		require.NoError(t, err)
		require.Equal(t, stakeBaseDenom, coin.Denom)
		require.Equal(t, sdkmath.NewInt(100000000000), coin.Amount)
	})

	t.Run("accepts base denom", func(t *testing.T) {
		coin, err := parseStakeAmount("100000000000uaeth")
		require.NoError(t, err)
		require.Equal(t, stakeBaseDenom, coin.Denom)
		require.Equal(t, sdkmath.NewInt(100000000000), coin.Amount)
	})

	t.Run("rejects unsupported denom", func(t *testing.T) {
		_, err := parseStakeAmount("100000foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported stake denom")
	})
}

func TestEnforceMinimumStake(t *testing.T) {
	t.Run("passes at minimum", func(t *testing.T) {
		coin, err := parseStakeAmount("100000aethel")
		require.NoError(t, err)
		require.NoError(t, enforceMinimumStake(coin))
	})

	t.Run("fails below minimum", func(t *testing.T) {
		coin, err := parseStakeAmount("99999aethel")
		require.NoError(t, err)
		require.Error(t, enforceMinimumStake(coin))
	})
}

func TestParseAssignedValidators(t *testing.T) {
	require.Equal(t, []string{"aethelred1abc", "aethelred1xyz"}, parseAssignedValidators(`["aethelred1abc","aethelred1xyz"]`))
	require.Equal(t, []string{"aethelred1abc", "aethelred1xyz"}, parseAssignedValidators(`aethelred1abc, aethelred1xyz`))
	require.Nil(t, parseAssignedValidators(""))
}

func TestAssignmentSnapshot(t *testing.T) {
	jobs := []*types.ComputeJob{
		{
			Metadata: map[string]string{
				schedulerMetaAssignedTo:   `["aethelred1validator"]`,
				schedulerMetaBeaconSource: dkgBeaconSource,
			},
		},
		{
			Metadata: map[string]string{
				schedulerMetaAssignedTo:   `["aethelred1validator"]`,
				schedulerMetaBeaconSource: "legacy-context-fallback",
			},
		},
		{
			Metadata: map[string]string{
				schedulerMetaAssignedTo: `["aethelred1other"]`,
			},
		},
	}

	assigned, dkg := assignmentSnapshot(jobs, map[string]struct{}{
		"aethelred1validator": {},
	})
	require.Equal(t, 2, assigned)
	require.Equal(t, 1, dkg)
}

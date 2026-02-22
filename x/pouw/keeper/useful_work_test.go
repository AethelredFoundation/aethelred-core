package keeper

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestCalculateUsefulWorkUnitsVTO_UsesMetadataAndModelBase(t *testing.T) {
	job := &types.ComputeJob{
		Metadata: map[string]string{
			workMetadataVTOKey: "420",
		},
	}
	model := &types.RegisteredModel{
		BaseUwuValue: 2048,
	}

	uwu, vto, paramSize := calculateUsefulWorkUnitsVTO(job, model, bytes.Repeat([]byte{0x01}, 32))
	require.EqualValues(t, 420, vto)
	require.EqualValues(t, 2048, paramSize)
	require.EqualValues(t, 420*2048, uwu)
}

func TestCalculateUsefulWorkUnitsVTO_FallsBackToOutputHashLenAndUnity(t *testing.T) {
	job := &types.ComputeJob{
		Metadata: map[string]string{},
	}

	uwu, vto, paramSize := calculateUsefulWorkUnitsVTO(job, nil, bytes.Repeat([]byte{0x02}, 32))
	require.EqualValues(t, 32, vto)
	require.EqualValues(t, 1, paramSize)
	require.EqualValues(t, 32, uwu)
}

func TestSaturatingMul_ClampsOverflow(t *testing.T) {
	result := saturatingMul(^uint64(0), 2)
	require.EqualValues(t, ^uint64(0), result)
}

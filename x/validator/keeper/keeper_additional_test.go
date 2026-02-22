package keeper_test

import (
	"fmt"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/validator/types"
)

func makeCapability(addr string, mode string, scoreBoost int32) *types.HardwareCapability {
	cap := types.NewHardwareCapability(addr, addr+"-op")
	cap.Status.Online = true
	cap.Status.ReputationScore = 80
	cap.Status.CurrentJobs = 0
	cap.Compute.MaxConcurrentJobs = 5
	cap.Compute.CpuCores = 16 + scoreBoost
	cap.Compute.MemoryGb = 64

	switch mode {
	case "tee":
		cap.AddTEEPlatform(&types.TEEPlatform{Name: "aws-nitro", SecurityLevel: 5})
	case "zkml":
		cap.AddProofSystem(&types.ProofSystem{Name: "ezkl", Version: "1.0"})
	case "hybrid":
		cap.AddTEEPlatform(&types.TEEPlatform{Name: "aws-nitro", SecurityLevel: 5})
		cap.AddProofSystem(&types.ProofSystem{Name: "ezkl", Version: "1.0"})
		cap.Zkml.GpuAccelerated = true
	}

	return cap
}

func TestKeeperRegisterAndFetchHardwareCapability(t *testing.T) {
	k, ctx := createTestKeeper(t)
	ctx = ctx.WithEventManager(sdk.NewEventManager())

	capability := makeCapability("validator-register", "hybrid", 2)
	require.NoError(t, k.RegisterHardwareCapability(ctx, capability))

	stored, err := k.GetHardwareCapability(ctx, capability.ValidatorAddress)
	require.NoError(t, err)
	require.True(t, stored.Status.Online)
	require.True(t, stored.CanHandleHybrid())

	events := ctx.EventManager().Events()
	require.NotEmpty(t, events)
	require.Equal(t, "hardware_capability_registered", events[0].Type)
}

func TestKeeperStatusHeartbeatAndErrors(t *testing.T) {
	k, ctx := createTestKeeper(t)

	capability := makeCapability("validator-status", "tee", 0)
	require.NoError(t, k.RegisterHardwareCapability(ctx, capability))

	require.NoError(t, k.UpdateValidatorStatus(ctx, capability.ValidatorAddress, true, 2))
	stored, err := k.GetHardwareCapability(ctx, capability.ValidatorAddress)
	require.NoError(t, err)
	require.EqualValues(t, 2, stored.Status.CurrentJobs)
	require.True(t, stored.Status.Online)
	require.NotNil(t, stored.Status.LastHeartbeat)

	require.NoError(t, k.RecordHeartbeat(ctx, capability.ValidatorAddress))
	stored, err = k.GetHardwareCapability(ctx, capability.ValidatorAddress)
	require.NoError(t, err)
	require.True(t, stored.Status.Online)
	require.NotNil(t, stored.Status.LastHeartbeat)

	// Missing validator heartbeat should create a minimal record.
	require.NoError(t, k.RecordHeartbeat(ctx, "validator-new"))
	minimal, err := k.GetHardwareCapability(ctx, "validator-new")
	require.NoError(t, err)
	require.True(t, minimal.Status.Online)

	require.Error(t, k.UpdateValidatorStatus(ctx, "missing-validator", true, 1))
	require.Error(t, k.RecordJobCompletion(ctx, "missing-validator", true, 10))
	require.Error(t, k.MarkValidatorOffline(ctx, "missing-validator"))
	_, err = k.GetValidatorStats(ctx, "missing-validator")
	require.Error(t, err)
}

func TestKeeperProofTypeFilteringSelectionAndStats(t *testing.T) {
	k, ctx := createTestKeeper(t)

	teeOnly := makeCapability("validator-tee", "tee", 0)
	zkOnly := makeCapability("validator-zk", "zkml", 0)
	hybrid := makeCapability("validator-hybrid", "hybrid", 8)

	require.NoError(t, k.RegisterHardwareCapability(ctx, teeOnly))
	require.NoError(t, k.RegisterHardwareCapability(ctx, zkOnly))
	require.NoError(t, k.RegisterHardwareCapability(ctx, hybrid))

	online := k.GetOnlineValidators(ctx)
	require.Len(t, online, 3)

	teeValidators := k.GetValidatorsForProofType(ctx, "tee")
	require.Len(t, teeValidators, 2)
	// Hybrid validator has higher score and should be selected first.
	require.Equal(t, "validator-hybrid", teeValidators[0].ValidatorAddress)

	hybridValidators := k.GetValidatorsForProofType(ctx, "hybrid")
	require.Len(t, hybridValidators, 1)
	require.Equal(t, "validator-hybrid", hybridValidators[0].ValidatorAddress)

	selected := k.SelectValidatorsForJob(ctx, "tee", 1)
	require.Len(t, selected, 1)
	require.Equal(t, "validator-hybrid", selected[0].ValidatorAddress)

	// Job completion should update rolling status fields.
	hybrid.Status.CurrentJobs = 1
	require.NoError(t, k.HardwareCapabilities.Set(ctx, hybrid.ValidatorAddress, *hybrid))
	require.NoError(t, k.RecordJobCompletion(ctx, hybrid.ValidatorAddress, true, 200))
	require.NoError(t, k.RecordJobCompletion(ctx, hybrid.ValidatorAddress, false, 100))

	stats, err := k.GetValidatorStats(ctx, hybrid.ValidatorAddress)
	require.NoError(t, err)
	require.EqualValues(t, 2, stats.TotalJobsProcessed)
	require.EqualValues(t, 0, stats.CurrentJobs)
	require.EqualValues(t, 190, stats.AverageLatencyMs)
	require.EqualValues(t, 76, stats.ReputationScore)
}

func TestKeeperInactiveAndOfflineTransitions(t *testing.T) {
	k, ctx := createTestKeeper(t)

	active := makeCapability("validator-active", "tee", 0)
	active.Status.LastHeartbeat = timestamppb.New(time.Now().Add(-4 * time.Hour))
	require.NoError(t, k.RegisterHardwareCapability(ctx, active))

	recent := makeCapability("validator-recent", "tee", 0)
	recent.Status.LastHeartbeat = timestamppb.New(time.Now())
	require.NoError(t, k.RegisterHardwareCapability(ctx, recent))

	k.CheckInactiveValidators(ctx, time.Hour)

	stale, err := k.GetHardwareCapability(ctx, active.ValidatorAddress)
	require.NoError(t, err)
	require.False(t, stale.Status.Online)

	online, err := k.GetHardwareCapability(ctx, recent.ValidatorAddress)
	require.NoError(t, err)
	require.True(t, online.Status.Online)

	require.NoError(t, k.MarkValidatorOffline(ctx, recent.ValidatorAddress))
	online, err = k.GetHardwareCapability(ctx, recent.ValidatorAddress)
	require.NoError(t, err)
	require.False(t, online.Status.Online)
}

func TestKeeperGenesisInitExportAndCollectionWalk(t *testing.T) {
	k, ctx := createTestKeeper(t)

	genesisCap := makeCapability("validator-genesis", "zkml", 0)
	gs := &types.GenesisState{
		Params: nil, // exercise default param path
		HardwareCapabilities: []*types.HardwareCapability{
			genesisCap,
		},
	}

	require.NoError(t, k.InitGenesis(ctx, gs))

	all := k.GetAllHardwareCapabilities(ctx)
	require.Len(t, all, 1)
	require.Equal(t, genesisCap.ValidatorAddress, all[0].ValidatorAddress)

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)
	require.NotNil(t, exported.Params)
	require.Len(t, exported.HardwareCapabilities, 1)

	err = k.InitGenesis(ctx, &types.GenesisState{
		Params:               types.DefaultParams(),
		HardwareCapabilities: []*types.HardwareCapability{nil},
	})
	require.Error(t, err)
}

func TestKeeperAuthorityAndRegistrationValidation(t *testing.T) {
	k, ctx := createTestKeeper(t)
	require.Equal(t, "authority", k.GetAuthority())

	invalid := types.NewHardwareCapability("", "")
	err := k.RegisterHardwareCapability(ctx, invalid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid hardware capability")
}

func TestKeeperRejectsValidatorBeyondMaxActiveCap(t *testing.T) {
	k, ctx := createTestKeeper(t)

	for i := 0; i < 100; i++ {
		capability := makeCapability(fmt.Sprintf("validator-cap-%d", i), "tee", 0)
		capability.Network = &types.NetworkInfo{Region: fmt.Sprintf("region-%d", i)}
		require.NoError(t, k.RegisterHardwareCapability(ctx, capability))
	}

	overflow := makeCapability("validator-cap-overflow", "tee", 0)
	overflow.Network = &types.NetworkInfo{Region: "overflow-region"}
	err := k.RegisterHardwareCapability(ctx, overflow)
	require.Error(t, err)
	require.Contains(t, err.Error(), "active validator cap reached")
}

func TestKeeperEnforcesZoneCap33Percent(t *testing.T) {
	k, ctx := createTestKeeper(t)

	first := makeCapability("validator-zone-1", "tee", 0)
	first.Network = &types.NetworkInfo{Region: "us-east-1"}
	require.NoError(t, k.RegisterHardwareCapability(ctx, first))

	second := makeCapability("validator-zone-2", "tee", 0)
	second.Network = &types.NetworkInfo{Region: "eu-central-1"}
	require.NoError(t, k.RegisterHardwareCapability(ctx, second))

	third := makeCapability("validator-zone-3", "tee", 0)
	third.Network = &types.NetworkInfo{Region: "us-east-1"}
	err := k.RegisterHardwareCapability(ctx, third)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds 33% zone cap")
}

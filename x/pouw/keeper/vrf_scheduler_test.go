package keeper_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestScheduler_PersistsVRFAssignmentMetadataChainBacked(t *testing.T) {
	k, ctx := newTestKeeper(t)
	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	params.AllowSimulated = true // legacy entropy fallback is test-only after production hardening
	require.NoError(t, k.SetParams(ctx, params))

	modelHash := bytes.Repeat([]byte{0x21}, 32)
	require.NoError(t, k.RegisterModel(ctx, &types.RegisteredModel{
		ModelHash:    modelHash,
		ModelId:      "vrf-model",
		Name:         "VRF Model",
		Version:      "1.0.0",
		Architecture: "transformer",
		Owner:        testAddr(1),
	}))

	require.NoError(t, k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(2),
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 2,
		IsOnline:          true,
		ReputationScore:   80,
	}))

	job := types.NewComputeJobWithBlockTime(
		modelHash,
		bytes.Repeat([]byte{0x11}, 32),
		testAddr(3),
		types.ProofTypeTEE,
		"vrf_test",
		sdk.NewInt64Coin("uaeth", 1000),
		ctx.BlockHeight(),
		ctx.BlockTime(),
	)
	// Keep Fee nil in tests to avoid proto v2/gogoproto math.Int marshal panics.
	job.Fee = nil
	require.NoError(t, k.SubmitJob(ctx, job))

	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, cfg)

	require.NoError(t, scheduler.SyncFromChain(ctx))
	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	require.Len(t, selected, 1)
	require.Equal(t, job.Id, selected[0].Id)

	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	require.NotNil(t, stored.Metadata)
	require.Equal(t, "pouw-vrf-v1", stored.Metadata["scheduler.vrf_version"])
	require.NotEmpty(t, stored.Metadata["scheduler.vrf_entropy"])
	require.NotEmpty(t, stored.Metadata["scheduler.vrf_assignments"])

	var records []keeper.VRFAssignmentRecord
	require.NoError(t, json.Unmarshal([]byte(stored.Metadata["scheduler.vrf_assignments"]), &records))
	require.Len(t, records, 1)
	require.Equal(t, testAddr(2), records[0].ValidatorAddress)
	require.True(t, records[0].Verified)
}

func TestScheduler_ProductionModeBlocksLegacyEntropyFallback(t *testing.T) {
	k, ctx := newTestKeeper(t)
	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	params.AllowSimulated = false
	require.NoError(t, k.SetParams(ctx, params))

	modelHash := bytes.Repeat([]byte{0x22}, 32)
	require.NoError(t, k.RegisterModel(ctx, &types.RegisteredModel{
		ModelHash:    modelHash,
		ModelId:      "prod-entropy-model",
		Name:         "Prod Entropy Model",
		Version:      "1.0.0",
		Architecture: "transformer",
		Owner:        testAddr(1),
	}))

	require.NoError(t, k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(2),
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 2,
		IsOnline:          true,
		ReputationScore:   80,
	}))

	job := types.NewComputeJobWithBlockTime(
		modelHash,
		bytes.Repeat([]byte{0x12}, 32),
		testAddr(3),
		types.ProofTypeTEE,
		"prod_entropy_fail_closed",
		sdk.NewInt64Coin("uaeth", 1000),
		ctx.BlockHeight(),
		ctx.BlockTime(),
	)
	job.Fee = nil
	require.NoError(t, k.SubmitJob(ctx, job))

	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	// Default config still allows legacy fallback for dev/test compatibility,
	// but production mode must block it at runtime.
	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, cfg)
	require.NoError(t, scheduler.SyncFromChain(ctx))

	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	require.Len(t, selected, 0)

	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	require.Equal(t, types.JobStatusPending, stored.Status)
}

func TestScheduler_UsesDKGBeaconEntropyAndPersistsBeaconMetadata(t *testing.T) {
	k, ctx := newTestKeeper(t)

	modelHash := bytes.Repeat([]byte{0x31}, 32)
	require.NoError(t, k.RegisterModel(ctx, &types.RegisteredModel{
		ModelHash:    modelHash,
		ModelId:      "dkg-model",
		Name:         "DKG Model",
		Version:      "1.0.0",
		Architecture: "transformer",
		Owner:        testAddr(1),
	}))

	require.NoError(t, k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(2),
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 2,
		IsOnline:          true,
		ReputationScore:   90,
	}))

	job := types.NewComputeJobWithBlockTime(
		modelHash,
		bytes.Repeat([]byte{0x41}, 32),
		testAddr(3),
		types.ProofTypeTEE,
		"dkg_entropy",
		sdk.NewInt64Coin("uaeth", 1000),
		ctx.BlockHeight(),
		ctx.BlockTime(),
	)
	job.Fee = nil
	require.NoError(t, k.SubmitJob(ctx, job))

	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	cfg.RequireDKGBeacon = true
	cfg.AllowLegacyEntropyFallback = false

	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, cfg)
	require.NoError(t, scheduler.SyncFromChain(ctx))

	payload := keeper.DKGBeaconPayload{
		Round:      77,
		Randomness: bytes.Repeat([]byte{0xAA}, 32),
		Signature:  bytes.Repeat([]byte{0xBB}, 96),
		Scheme:     "dkg-threshold-bls-v1",
	}
	ctxWithBeacon := keeper.WithDKGBeaconPayload(ctx, payload)

	selected := scheduler.GetNextJobs(ctxWithBeacon, ctx.BlockHeight())
	require.Len(t, selected, 1)
	require.Equal(t, job.Id, selected[0].Id)

	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	require.Equal(t, "dkg-threshold-beacon", stored.Metadata["scheduler.beacon_source"])
	require.Equal(t, "dkg-threshold-bls-v1", stored.Metadata["scheduler.beacon_version"])
	require.Equal(t, "77", stored.Metadata["scheduler.beacon_round"])

	wantSigHash := sha256.Sum256(payload.Signature)
	require.Equal(t, bytes.Repeat([]byte{0xaa}, 32), mustDecodeHex(t, stored.Metadata["scheduler.beacon_randomness"]))
	require.Equal(t, wantSigHash[:], mustDecodeHex(t, stored.Metadata["scheduler.beacon_signature_hash"]))
}

func TestScheduler_StrictDKGModeRejectsMissingBeaconEntropy(t *testing.T) {
	k, ctx := newTestKeeper(t)

	modelHash := bytes.Repeat([]byte{0x51}, 32)
	require.NoError(t, k.RegisterModel(ctx, &types.RegisteredModel{
		ModelHash:    modelHash,
		ModelId:      "strict-dkg-model",
		Name:         "Strict DKG Model",
		Version:      "1.0.0",
		Architecture: "transformer",
		Owner:        testAddr(1),
	}))

	require.NoError(t, k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           testAddr(2),
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 2,
		IsOnline:          true,
		ReputationScore:   90,
	}))

	job := types.NewComputeJobWithBlockTime(
		modelHash,
		bytes.Repeat([]byte{0x61}, 32),
		testAddr(3),
		types.ProofTypeTEE,
		"strict_dkg",
		sdk.NewInt64Coin("uaeth", 1000),
		ctx.BlockHeight(),
		ctx.BlockTime(),
	)
	job.Fee = nil
	require.NoError(t, k.SubmitJob(ctx, job))

	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	cfg.RequireDKGBeacon = true
	cfg.AllowLegacyEntropyFallback = false

	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, cfg)
	require.NoError(t, scheduler.SyncFromChain(ctx))

	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	require.Len(t, selected, 0)

	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	// Job remains pending when strict DKG entropy is missing.
	require.Equal(t, types.JobStatusPending, stored.Status)
}

func mustDecodeHex(t *testing.T, hexValue string) []byte {
	t.Helper()
	out, err := hex.DecodeString(hexValue)
	require.NoError(t, err)
	return out
}

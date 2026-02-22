package keeper

import (
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func testSDKContext(height int64) sdk.Context {
	header := tmproto.Header{
		Height:  height,
		Time:    time.Unix(1_700_000_000, 0).UTC(),
		ChainID: "aethelred-test-1",
	}
	return sdk.NewContext(nil, header, false, log.NewNopLogger())
}

func h(b byte) [32]byte {
	var out [32]byte
	out[0] = b
	return out
}

func TestBlockMissTrackerAndPenalties(t *testing.T) {
	cfg := BlockMissConfig{
		ParticipationWindow: 10,
		MaxMissedBlocks:     2,
		JailThreshold:       3,
		DowntimeSlashBps:    100,
	}
	tracker := NewBlockMissTracker(log.NewNopLogger(), nil, cfg)
	require.Equal(t, int64(0), tracker.GetMissCount("val1"))

	tracker.RecordMiss("val1", 1)
	tracker.RecordMiss("val1", 2)
	require.Equal(t, int64(2), tracker.GetMissCount("val1"))
	require.True(t, tracker.ShouldSlash("val1"))
	require.False(t, tracker.ShouldJail("val1"))

	tracker.RecordMiss("val1", 3)
	require.True(t, tracker.ShouldJail("val1"))

	// Prune old misses via participation updates.
	tracker.RecordParticipation("val1", 20)
	require.Equal(t, int64(0), tracker.GetMissCount("val1"))

	tracker.RecordMiss("val1", 25)
	tracker.RecordMiss("val1", 26)
	tracker.RecordMiss("val2", 25)
	tracker.RecordMiss("val2", 26)
	tracker.RecordMiss("val2", 27)

	penalties := tracker.CheckAndApplyDowntimePenalties(testSDKContext(30))
	require.Len(t, penalties, 2)
	actions := map[string]DowntimeAction{
		penalties[0].ValidatorAddress: penalties[0].Action,
		penalties[1].ValidatorAddress: penalties[1].Action,
	}
	require.Equal(t, DowntimeActionSlash, actions["val1"])
	require.Equal(t, DowntimeActionJail, actions["val2"])
}

func TestDoubleVotingDetectorLifecycle(t *testing.T) {
	detector := NewDoubleVotingDetector(log.NewNopLogger(), nil)
	extHash := h(9)

	outputsA := map[string][32]byte{"job-1": h(1)}
	outputsB := map[string][32]byte{"job-1": h(2)}

	// First vote is accepted.
	require.Nil(t, detector.RecordVote("val1", 100, extHash, outputsA))
	// Replaying the same vote hash is not equivocation.
	require.Nil(t, detector.RecordVote("val1", 100, extHash, outputsA))

	evidence := detector.RecordVote("val1", 100, extHash, outputsB)
	require.NotNil(t, evidence)
	require.Equal(t, "val1", evidence.ValidatorAddress)
	require.EqualValues(t, 100, evidence.BlockHeight)
	require.NotEqual(t, evidence.Vote1.VoteHash, evidence.Vote2.VoteHash)
	require.NotEqual(t, [32]byte{}, evidence.EvidenceHash)
	require.True(t, VerifyEquivocationEvidence(evidence))

	pending := detector.GetPendingEquivocations()
	require.Len(t, pending, 1)

	detector.ClearProcessedEquivocations([][32]byte{pending[0].EvidenceHash})
	require.Empty(t, detector.GetPendingEquivocations())

	// Height pruning should remove older vote history buckets.
	require.Nil(t, detector.RecordVote("val1", 50, extHash, outputsA))
	detector.PruneOldHistory(60)
	// No panic and history path remains usable after prune.
	require.Nil(t, detector.RecordVote("val1", 70, extHash, outputsA))
}

func TestEvidenceVerificationRejectsInvalid(t *testing.T) {
	e := &EquivocationEvidence{
		ValidatorAddress: "val1",
		BlockHeight:      123,
		Vote1:            VoteRecord{VoteHash: h(1)},
		Vote2:            VoteRecord{VoteHash: h(2)},
	}
	e.EvidenceHash = computeEvidenceHashStatic(e)
	require.True(t, VerifyEquivocationEvidence(e))

	// Same vote hash means no equivocation.
	eSame := *e
	eSame.Vote2 = VoteRecord{VoteHash: eSame.Vote1.VoteHash}
	eSame.EvidenceHash = computeEvidenceHashStatic(&eSame)
	require.False(t, VerifyEquivocationEvidence(&eSame))

	// Tampered evidence hash must fail verification.
	eBad := *e
	eBad.EvidenceHash = h(99)
	require.False(t, VerifyEquivocationEvidence(&eBad))
}

func TestSlashingIntegrationAndCollusion(t *testing.T) {
	ctx := testSDKContext(200)
	slash := NewSlashingIntegration(log.NewNopLogger(), nil, DefaultEvidenceSlashingConfig())

	penalty := &DowntimePenalty{
		ValidatorAddress: "val1",
		MissedBlocks:     10,
		Action:           DowntimeActionJail,
		BlockHeight:      199,
	}
	downtimeRes, err := slash.ProcessDowntimeEvidence(ctx, penalty)
	require.NoError(t, err)
	require.Equal(t, SlashReasonDowntime, downtimeRes.Reason)
	require.True(t, downtimeRes.Jailed)
	require.True(t, downtimeRes.SlashedAmount.GT(sdkmath.ZeroInt()))

	detector := NewDoubleVotingDetector(log.NewNopLogger(), nil)
	require.Nil(t, detector.RecordVote("val2", 201, h(7), map[string][32]byte{"job-1": h(1)}))
	evidence := detector.RecordVote("val2", 201, h(7), map[string][32]byte{"job-1": h(3)})
	require.NotNil(t, evidence)

	doubleSignRes, err := slash.ProcessDoubleSignEvidence(ctx, evidence)
	require.NoError(t, err)
	require.Equal(t, SlashReasonDoubleSign, doubleSignRes.Reason)
	require.True(t, doubleSignRes.Jailed)
	require.True(t, doubleSignRes.SlashedAmount.GT(sdkmath.ZeroInt()))

	collusion, err := slash.ProcessCollusionEvidence(ctx, []string{"val3", "val4"}, 201, "same invalid output")
	require.NoError(t, err)
	require.Len(t, collusion, 2)
	for _, r := range collusion {
		require.Equal(t, SlashReasonCollusion, r.Reason)
		require.True(t, r.Jailed)
		require.True(t, r.SlashedAmount.GT(sdkmath.ZeroInt()))
	}
}

func TestEvidenceProcessorEndBlockFlow(t *testing.T) {
	ctx := testSDKContext(500)
	missCfg := BlockMissConfig{
		ParticipationWindow: 100,
		MaxMissedBlocks:     1,
		JailThreshold:       2,
		DowntimeSlashBps:    100,
	}
	ep := NewEvidenceProcessor(log.NewNopLogger(), nil, missCfg, DefaultEvidenceSlashingConfig())

	ep.RecordValidatorMiss(ctx, "val1")
	ep.RecordValidatorMiss(ctx, "val2")
	ep.RecordValidatorMiss(ctx, "val2")

	ext := h(4)
	require.Nil(t, ep.RecordValidatorParticipation(ctx, "val3", ext, map[string][32]byte{"job-x": h(10)}))
	require.NotNil(t, ep.RecordValidatorParticipation(ctx, "val3", ext, map[string][32]byte{"job-x": h(11)}))

	res := ep.ProcessEndBlockEvidence(ctx)
	require.EqualValues(t, 500, res.BlockHeight)
	require.NotZero(t, res.ProcessedAt.Unix())
	require.Len(t, res.DowntimePenalties, 2)
	require.Len(t, res.EquivocationSlashes, 1)
	require.True(t, res.TotalSlashed().GT(sdkmath.ZeroInt()))

	// Equivocations are cleared after processing.
	second := ep.ProcessEndBlockEvidence(ctx)
	require.Len(t, second.EquivocationSlashes, 0)
}

func TestCollusionDetectorThresholdAndCapture(t *testing.T) {
	// Threshold < 2 must auto-correct to 2.
	cd := NewCollusionDetector(log.NewNopLogger(), 1)
	invalid := h(42)
	require.Nil(t, cd.RecordInvalidOutput("val1", "job-1", invalid, 100))
	e := cd.RecordInvalidOutput("val2", "job-1", invalid, 100)
	require.NotNil(t, e)
	require.Len(t, e.Validators, 2)

	all := cd.GetDetectedCollusions()
	require.Len(t, all, 1)
	require.Equal(t, "job-1", all[0].JobID)
}

func TestDefaultEvidenceConfigs(t *testing.T) {
	b := DefaultBlockMissConfig()
	require.Greater(t, b.ParticipationWindow, int64(0))
	require.Greater(t, b.MaxMissedBlocks, int64(0))
	require.GreaterOrEqual(t, b.JailThreshold, b.MaxMissedBlocks)
	require.Greater(t, b.DowntimeSlashBps, int64(0))

	s := DefaultEvidenceSlashingConfig()
	require.Greater(t, s.DoubleSignSlashBps, int64(0))
	require.Greater(t, s.InvalidOutputSlashBps, int64(0))
	require.Greater(t, s.CollusionSlashBps, int64(0))
	require.Greater(t, s.DoubleSignJailDuration, time.Duration(0))
}


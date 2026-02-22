package keeper

import (
	"testing"
	"time"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func newEvidenceSDKContext(height int64) sdk.Context {
	return sdk.NewContext(nil, tmproto.Header{
		Height:  height,
		Time:    time.Unix(1_700_000_500, 0).UTC(),
		ChainID: "aethelred-test-1",
	}, false, log.NewNopLogger())
}

func TestLegacyMissedBlockTracker(t *testing.T) {
	tracker := NewMissedBlockTracker(2)
	require.EqualValues(t, 2, tracker.GetThreshold())
	require.EqualValues(t, 0, tracker.GetMissedCount("val1"))
	require.EqualValues(t, 0, tracker.GetLastSignedHeight("val1"))

	tracker.RecordSignature("val1", 10)
	require.EqualValues(t, 0, tracker.GetMissedCount("val1"))
	require.EqualValues(t, 10, tracker.GetLastSignedHeight("val1"))

	reached := tracker.RecordMiss("val1", 11)
	require.False(t, reached)
	require.EqualValues(t, 1, tracker.GetMissedCount("val1"))

	reached = tracker.RecordMiss("val1", 12)
	require.True(t, reached)
	require.EqualValues(t, 2, tracker.GetMissedCount("val1"))

	tracker.Reset("val1")
	require.EqualValues(t, 0, tracker.GetMissedCount("val1"))

	defaulted := NewMissedBlockTracker(0)
	require.EqualValues(t, 100, defaulted.GetThreshold())
}

func TestEvidenceCollectorEndBlockWithoutKeepers(t *testing.T) {
	ctx := newEvidenceSDKContext(333)
	ec := NewEvidenceCollector(log.NewNopLogger(), nil)
	require.NoError(t, ec.ProcessEndBlockEvidence(ctx))
	require.Empty(t, ec.checkMissedBlocks(ctx, 10))
}

func TestEvidenceCollectorApplySlashingInvalidAddress(t *testing.T) {
	ctx := newEvidenceSDKContext(444)
	k := &Keeper{}
	ec := NewEvidenceCollector(log.NewNopLogger(), k)

	records := []SlashingEvidenceRecord{
		{
			ValidatorAddress: "not-a-valid-bech32",
			Condition:        "double_sign",
			Severity:         "critical",
			JobID:            "job-1",
			BlockHeight:      444,
			DetectedBy:       "test",
		},
	}

	// A zero-initialized keeper does not have initialized collections and should
	// fail fast rather than silently proceeding with slashing logic.
	require.Panics(t, func() {
		_ = ec.ApplySlashingPenalties(ctx, records)
	})
}

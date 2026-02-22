package keeper_test

import (
	"testing"
	"time"

	"cosmossdk.io/log"
	"cosmossdk.io/store"
	"cosmossdk.io/store/metrics"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/validator/keeper"
	"github.com/aethelred/aethelred/x/validator/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// createTestKeeper builds a Keeper backed by an in-memory IAVL store so that
// collections (HardwareCapabilities, SlashingRecords, Params) work correctly.
func createTestKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	memStoreKey := storetypes.NewMemoryStoreKey("mem_" + types.StoreKey)

	db := dbm.NewMemDB()
	stateStore := store.NewCommitMultiStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	stateStore.MountStoreWithDB(memStoreKey, storetypes.StoreTypeMemory, nil)
	err := stateStore.LoadLatestVersion()
	require.NoError(t, err)

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)

	storeService := runtime.NewKVStoreService(storeKey)

	ctx := sdk.NewContext(stateStore, tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Now().UTC(),
	}, false, log.NewNopLogger())

	k := keeper.NewKeeper(cdc, storeService, log.NewNopLogger(), nil, nil, "authority")

	return k, ctx
}

// setupValidatorWithReputation registers a HardwareCapability for the given
// address with the specified reputation score and Online=true.
func setupValidatorWithReputation(t *testing.T, k keeper.Keeper, ctx sdk.Context, addr string, reputation int64) {
	t.Helper()
	cap := types.HardwareCapability{
		ValidatorAddress: addr,
		Status: &types.CapabilityStatus{
			Online:          true,
			ReputationScore: reputation,
		},
	}
	err := k.HardwareCapabilities.Set(ctx, addr, cap)
	require.NoError(t, err)
}

// ===========================================================================
// Section 1 -- SlashValidator
// ===========================================================================

func TestSlashValidator_InvalidOutput(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_invalid_output"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	err := k.SlashValidator(ctx, addr, keeper.SlashingConditionInvalidOutput, keeper.SlashingEvidence{}, "job-1")
	require.NoError(t, err)

	// Verify slashing record
	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 1)
	require.Equal(t, "1.00", records[0].SlashFraction)
	require.Equal(t, string(keeper.SlashingConditionInvalidOutput), records[0].Reason)
	require.True(t, records[0].Jailed)
	require.Equal(t, "job-1", records[0].JobId)

	// Verify reputation: 100 - 100 = 0
	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, int64(0), cap.Status.ReputationScore)
	require.False(t, cap.Status.Online)
}

func TestSlashValidator_FakeAttestation(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_fake_attest"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	err := k.SlashValidator(ctx, addr, keeper.SlashingConditionFakeAttestation, keeper.SlashingEvidence{}, "job-2")
	require.NoError(t, err)

	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 1)
	require.Equal(t, "1.00", records[0].SlashFraction)
	require.True(t, records[0].Jailed)

	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, int64(0), cap.Status.ReputationScore) // 100 - 100
	require.False(t, cap.Status.Online)                    // jailed -> offline
}

func TestSlashValidator_DoubleSign(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_double_sign"
	setupValidatorWithReputation(t, k, ctx, addr, 80)

	err := k.SlashValidator(ctx, addr, keeper.SlashingConditionDoubleSign, keeper.SlashingEvidence{}, "job-3")
	require.NoError(t, err)

	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 1)
	require.Equal(t, "0.50", records[0].SlashFraction)
	require.True(t, records[0].Jailed)

	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, int64(40), cap.Status.ReputationScore) // 80 - 40
	require.False(t, cap.Status.Online)
}

func TestSlashValidator_Collusion(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_collusion"
	setupValidatorWithReputation(t, k, ctx, addr, 90)

	err := k.SlashValidator(ctx, addr, keeper.SlashingConditionCollusion, keeper.SlashingEvidence{}, "job-4")
	require.NoError(t, err)

	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 1)
	require.Equal(t, "1.00", records[0].SlashFraction)
	require.True(t, records[0].Jailed)

	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, int64(0), cap.Status.ReputationScore) // 90 - 90 = 0
	require.False(t, cap.Status.Online)
}

func TestSlashValidator_Downtime(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_downtime"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	err := k.SlashValidator(ctx, addr, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, "")
	require.NoError(t, err)

	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 1)
	require.Equal(t, "0.05", records[0].SlashFraction)
	require.True(t, records[0].Jailed)

	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	// 100 - int64(100 * 0.05) = 100 - 5 = 95
	require.Equal(t, int64(95), cap.Status.ReputationScore)
	require.False(t, cap.Status.Online)

	jailedUntil, err := k.ValidatorJailUntil.Get(ctx, addr)
	require.NoError(t, err)
	require.Greater(t, jailedUntil, ctx.BlockTime().Unix())
}

func TestSlashDowntimeAndSlashFraudWrappers(t *testing.T) {
	k, ctx := createTestKeeper(t)

	downtimeAddr := "cosmosvaloper1wrapper_downtime"
	setupValidatorWithReputation(t, k, ctx, downtimeAddr, 100)
	require.NoError(t, k.SlashDowntime(ctx, downtimeAddr, []int64{1, 2, 3}))

	fraudAddr := "cosmosvaloper1wrapper_fraud"
	setupValidatorWithReputation(t, k, ctx, fraudAddr, 100)
	require.NoError(t, k.SlashFraud(ctx, fraudAddr, "job-fraud", []byte("exp"), []byte("act")))

	records := k.GetSlashingRecords(ctx, fraudAddr)
	require.Len(t, records, 1)
	require.Equal(t, "1.00", records[0].SlashFraction)
}

func TestSlashValidator_UnknownCondition(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_unknown"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	err := k.SlashValidator(ctx, addr, keeper.SlashingCondition("nonexistent_condition"), keeper.SlashingEvidence{}, "job-x")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown slashing condition")

	// No record should have been stored
	records := k.GetSlashingRecords(ctx, addr)
	require.Empty(t, records)

	// Reputation unchanged
	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, int64(100), cap.Status.ReputationScore)
}

func TestSlashValidator_AlreadyZeroReputation(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_zero_rep"
	setupValidatorWithReputation(t, k, ctx, addr, 0)

	err := k.SlashValidator(ctx, addr, keeper.SlashingConditionCollusion, keeper.SlashingEvidence{}, "job-5")
	require.NoError(t, err)

	// Reputation must not go negative -- clamped at 0
	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, int64(0), cap.Status.ReputationScore)
}

func TestSlashValidator_MultipleSlashesAccumulate(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1test_multi_slash"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	// First slash at height 100 (invalid proof, 10%)
	err := k.SlashValidator(ctx, addr, keeper.SlashingConditionInvalidProof, keeper.SlashingEvidence{}, "job-a")
	require.NoError(t, err)

	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, int64(90), cap.Status.ReputationScore)

	// Advance block height so the record key is different
	ctx = ctx.WithBlockHeight(101)

	// Second slash at height 101 (downtime, 5%)
	err = k.SlashValidator(ctx, addr, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, "job-b")
	require.NoError(t, err)

	cap, err = k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	// 90 - int64(90 * 0.05) = 90 - 4 = 86
	require.Equal(t, int64(86), cap.Status.ReputationScore)

	// Both records should be retrievable
	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 2)
}

// ===========================================================================
// Section 2 -- ReportMisbehavior
// ===========================================================================

func TestReportMisbehavior_ValidInvalidOutput(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1target"
	reporter := "cosmos1reporter"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	report := &keeper.SlashingReport{
		ReporterAddress:  reporter,
		ValidatorAddress: addr,
		Condition:        keeper.SlashingConditionInvalidOutput,
		JobID:            "job-r1",
		Evidence: keeper.SlashingEvidence{
			ExpectedOutput: []byte("expected"),
			ActualOutput:   []byte("actual"),
		},
	}

	err := k.ReportMisbehavior(ctx, report)
	require.NoError(t, err)

	// The report should have triggered a slash
	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 1)
	require.Equal(t, "1.00", records[0].SlashFraction)
}

func TestReportMisbehavior_MissingValidatorAddress(t *testing.T) {
	k, ctx := createTestKeeper(t)

	report := &keeper.SlashingReport{
		ReporterAddress:  "cosmos1reporter",
		ValidatorAddress: "", // missing
		Condition:        keeper.SlashingConditionInvalidOutput,
		Evidence: keeper.SlashingEvidence{
			ExpectedOutput: []byte("e"),
			ActualOutput:   []byte("a"),
		},
	}

	err := k.ReportMisbehavior(ctx, report)
	require.Error(t, err)
	require.Contains(t, err.Error(), "validator address cannot be empty")
}

func TestReportMisbehavior_MissingReporterAddress(t *testing.T) {
	k, ctx := createTestKeeper(t)

	report := &keeper.SlashingReport{
		ReporterAddress:  "", // missing
		ValidatorAddress: "cosmosvaloper1x",
		Condition:        keeper.SlashingConditionInvalidOutput,
		Evidence: keeper.SlashingEvidence{
			ExpectedOutput: []byte("e"),
			ActualOutput:   []byte("a"),
		},
	}

	err := k.ReportMisbehavior(ctx, report)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reporter address cannot be empty")
}

func TestReportMisbehavior_InvalidOutputMissingEvidence(t *testing.T) {
	k, ctx := createTestKeeper(t)

	report := &keeper.SlashingReport{
		ReporterAddress:  "cosmos1reporter",
		ValidatorAddress: "cosmosvaloper1x",
		Condition:        keeper.SlashingConditionInvalidOutput,
		Evidence:         keeper.SlashingEvidence{}, // no expected/actual
	}

	err := k.ReportMisbehavior(ctx, report)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid output condition requires expected and actual outputs")
}

func TestReportMisbehavior_FakeAttestationMissingEvidence(t *testing.T) {
	k, ctx := createTestKeeper(t)

	report := &keeper.SlashingReport{
		ReporterAddress:  "cosmos1reporter",
		ValidatorAddress: "cosmosvaloper1x",
		Condition:        keeper.SlashingConditionFakeAttestation,
		Evidence:         keeper.SlashingEvidence{}, // no attestation data
	}

	err := k.ReportMisbehavior(ctx, report)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fake attestation condition requires attestation data")
}

func TestReportMisbehavior_DoubleSignInsufficientResults(t *testing.T) {
	k, ctx := createTestKeeper(t)

	// Only 1 result -- need at least 2
	report := &keeper.SlashingReport{
		ReporterAddress:  "cosmos1reporter",
		ValidatorAddress: "cosmosvaloper1x",
		Condition:        keeper.SlashingConditionDoubleSign,
		Evidence: keeper.SlashingEvidence{
			ConflictingResults: []keeper.OutputWithTimestamp{
				{OutputHash: []byte("hash1"), Timestamp: time.Now(), Height: 50},
			},
		},
	}

	err := k.ReportMisbehavior(ctx, report)
	require.Error(t, err)
	require.Contains(t, err.Error(), "double sign condition requires at least 2 conflicting results")
}

// ===========================================================================
// Section 3 -- DetectInvalidOutput
// ===========================================================================

func TestDetectInvalidOutput_DifferentOutputs(t *testing.T) {
	k, ctx := createTestKeeper(t)
	detected := k.DetectInvalidOutput(ctx, "val1", "job-1", []byte("output-a"), []byte("output-b"))
	require.True(t, detected)
}

func TestDetectInvalidOutput_SameOutputs(t *testing.T) {
	k, ctx := createTestKeeper(t)
	detected := k.DetectInvalidOutput(ctx, "val1", "job-1", []byte("same"), []byte("same"))
	require.False(t, detected)
}

func TestDetectInvalidOutput_DifferentLengths(t *testing.T) {
	k, ctx := createTestKeeper(t)
	detected := k.DetectInvalidOutput(ctx, "val1", "job-1", []byte("short"), []byte("longer-output"))
	require.True(t, detected)
}

func TestDetectInvalidOutput_EmptyOutputs(t *testing.T) {
	k, ctx := createTestKeeper(t)
	detected := k.DetectInvalidOutput(ctx, "val1", "job-1", []byte{}, []byte{})
	require.False(t, detected)
}

// ===========================================================================
// Section 4 -- DetectDoubleSign
// ===========================================================================

func TestDetectDoubleSign_TwoConflictingResults(t *testing.T) {
	k, ctx := createTestKeeper(t)
	results := []keeper.OutputWithTimestamp{
		{OutputHash: []byte("hash-1"), Timestamp: time.Now(), Height: 100},
		{OutputHash: []byte("hash-2"), Timestamp: time.Now(), Height: 100},
	}
	require.True(t, k.DetectDoubleSign(ctx, "val1", "job-1", results))
}

func TestDetectDoubleSign_IdenticalResults(t *testing.T) {
	k, ctx := createTestKeeper(t)
	results := []keeper.OutputWithTimestamp{
		{OutputHash: []byte("same-hash"), Timestamp: time.Now(), Height: 100},
		{OutputHash: []byte("same-hash"), Timestamp: time.Now(), Height: 101},
	}
	require.False(t, k.DetectDoubleSign(ctx, "val1", "job-1", results))
}

func TestDetectDoubleSign_SingleResult(t *testing.T) {
	k, ctx := createTestKeeper(t)
	results := []keeper.OutputWithTimestamp{
		{OutputHash: []byte("only-one"), Timestamp: time.Now(), Height: 100},
	}
	require.False(t, k.DetectDoubleSign(ctx, "val1", "job-1", results))
}

func TestDetectDoubleSign_ThreeResultsWithConflict(t *testing.T) {
	k, ctx := createTestKeeper(t)
	results := []keeper.OutputWithTimestamp{
		{OutputHash: []byte("hash-a"), Timestamp: time.Now(), Height: 100},
		{OutputHash: []byte("hash-a"), Timestamp: time.Now(), Height: 101},
		{OutputHash: []byte("hash-b"), Timestamp: time.Now(), Height: 102}, // conflict
	}
	require.True(t, k.DetectDoubleSign(ctx, "val1", "job-1", results))
}

// ===========================================================================
// Section 5 -- GetSlashingRecords / GetRecentSlashingRecords
// ===========================================================================

func TestGetSlashingRecords_Empty(t *testing.T) {
	k, ctx := createTestKeeper(t)
	records := k.GetSlashingRecords(ctx, "cosmosvaloper1nonexistent")
	require.Empty(t, records)
}

func TestGetSlashingRecords_MultipleRecords(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1multi"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	// Slash at height 100
	require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, ""))

	// Slash at height 101
	ctx = ctx.WithBlockHeight(101)
	require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionInvalidProof, keeper.SlashingEvidence{}, "job-m"))

	// Slash at height 102
	ctx = ctx.WithBlockHeight(102)
	require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, "job-n"))

	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 3)
}

func TestGetSlashingRecords_FiltersByValidator(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addrA := "cosmosvaloper1filterA"
	addrB := "cosmosvaloper1filterB"
	setupValidatorWithReputation(t, k, ctx, addrA, 100)
	setupValidatorWithReputation(t, k, ctx, addrB, 100)

	// Slash validator A at height 100
	require.NoError(t, k.SlashValidator(ctx, addrA, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, ""))

	// Slash validator B at height 101
	ctx = ctx.WithBlockHeight(101)
	require.NoError(t, k.SlashValidator(ctx, addrB, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, ""))

	// Slash validator A again at height 102
	ctx = ctx.WithBlockHeight(102)
	require.NoError(t, k.SlashValidator(ctx, addrA, keeper.SlashingConditionInvalidOutput, keeper.SlashingEvidence{}, "job-f"))

	recordsA := k.GetSlashingRecords(ctx, addrA)
	require.Len(t, recordsA, 2)

	recordsB := k.GetSlashingRecords(ctx, addrB)
	require.Len(t, recordsB, 1)
}

func TestGetRecentSlashingRecords_RespectsLimit(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1recent"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	for i := int64(0); i < 5; i++ {
		ctx = ctx.WithBlockHeight(100 + i)
		require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, ""))
	}

	recent := k.GetRecentSlashingRecords(ctx, 3)
	require.Len(t, recent, 3)
}

// ===========================================================================
// Section 6 -- Deterministic slashing behaviour
// ===========================================================================

func TestSlashValidator_DeterministicReputationReduction(t *testing.T) {
	// Verify that identical starting conditions always yield the same result.
	startingReputations := []int64{100, 80, 50, 10, 1}

	for _, rep := range startingReputations {
		k, ctx := createTestKeeper(t)
		addr := "cosmosvaloper1determ"
		setupValidatorWithReputation(t, k, ctx, addr, rep)

		require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionInvalidProof, keeper.SlashingEvidence{}, "job-d"))

		cap, err := k.GetHardwareCapability(ctx, addr)
		require.NoError(t, err)

		// penalty = int64(float64(rep) * 0.10)
		expectedPenalty := int64(float64(rep) * 0.10)
		expectedRep := rep - expectedPenalty
		if expectedRep < 0 {
			expectedRep = 0
		}
		require.Equal(t, expectedRep, cap.Status.ReputationScore,
			"starting reputation %d should yield %d after 10%% slash", rep, expectedRep)
	}
}

func TestSlashValidator_ReputationFloorAtZero(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1floor"
	setupValidatorWithReputation(t, k, ctx, addr, 5)

	// Repeatedly slash -- reputation must never go below 0
	for i := int64(0); i < 10; i++ {
		ctx = ctx.WithBlockHeight(100 + i)
		require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionInvalidProof, keeper.SlashingEvidence{}, ""))
	}

	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.GreaterOrEqual(t, cap.Status.ReputationScore, int64(0))
}

func TestSlashValidator_JailingSideEffect(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1jail_persist"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	// Jailable condition
	require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionDoubleSign, keeper.SlashingEvidence{}, "job-j"))

	// Read back from store -- Online must be false (jailed)
	cap, err := k.GetHardwareCapability(ctx, addr)
	require.NoError(t, err)
	require.False(t, cap.Status.Online, "validator should be jailed (Online=false)")

	// The slashing record itself should also reflect jailing
	records := k.GetSlashingRecords(ctx, addr)
	require.Len(t, records, 1)
	require.True(t, records[0].Jailed)
}

func TestSlashValidator_InvalidOutputTombstonesValidator(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1tombstone"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionInvalidOutput, keeper.SlashingEvidence{}, "job-t"))

	tombstoned, err := k.TombstonedValidators.Has(ctx, addr)
	require.NoError(t, err)
	require.True(t, tombstoned)

	// Any further slash attempts should fail because validator is permanently banned.
	err = k.SlashValidator(ctx.WithBlockHeight(ctx.BlockHeight()+1), addr, keeper.SlashingConditionInvalidProof, keeper.SlashingEvidence{}, "job-next")
	require.Error(t, err)
	require.Contains(t, err.Error(), "permanently tombstoned")
}

func TestSlashValidator_DowntimeJailExpiresAfterOneHour(t *testing.T) {
	k, ctx := createTestKeeper(t)
	addr := "cosmosvaloper1downtimejail"
	setupValidatorWithReputation(t, k, ctx, addr, 100)

	require.NoError(t, k.SlashValidator(ctx, addr, keeper.SlashingConditionDowntime, keeper.SlashingEvidence{}, "job-dt"))

	cap := makeCapability(addr, "tee", 0)
	cap.Network = &types.NetworkInfo{Region: "us-east-1"}
	err := k.RegisterHardwareCapability(ctx, cap)
	require.Error(t, err)
	require.Contains(t, err.Error(), "temporarily jailed")

	// Advance more than 1 hour to clear the temporary jail.
	ctx = ctx.WithBlockTime(ctx.BlockTime().Add(2 * time.Hour))
	require.NoError(t, k.RegisterHardwareCapability(ctx, cap))
}

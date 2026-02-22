package keeper_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	storemetrics "cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEK 21-26: DevEx, Load Tests, Upgrade Readiness & Validator Onboarding
//
// These tests cover:
//   1.  Query server (9 tests)
//   2.  Upgrade & migration (10 tests)
//   3.  Genesis round-trip (5 tests)
//   4.  Load & stress tests (6 tests)
//   5.  Benchmarks for critical paths (6 benchmarks)
//
// Total: 30 tests + 6 benchmarks
// =============================================================================

// ---------------------------------------------------------------------------
// Test keeper factory (creates a real keeper with in-memory state)
// ---------------------------------------------------------------------------

// mockBankKeeper is a minimal no-op bank keeper for testing query and
// upgrade paths that don't exercise economic operations.
type mockBankKeeper struct{}

func (m mockBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, _ sdk.AccAddress, _ sdk.Coins) error {
	return nil
}
func (m mockBankKeeper) SendCoinsFromAccountToModule(_ context.Context, _ sdk.AccAddress, _ string, _ sdk.Coins) error {
	return nil
}
func (m mockBankKeeper) SendCoinsFromModuleToModule(_ context.Context, _, _ string, _ sdk.Coins) error {
	return nil
}
func (m mockBankKeeper) BurnCoins(_ context.Context, _ string, _ sdk.Coins) error { return nil }
func (m mockBankKeeper) SpendableCoins(_ context.Context, _ sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins(sdk.NewInt64Coin("uaeth", 1000000))
}

// mockStakingKeeper is a minimal staking keeper stub.
type mockStakingKeeper struct{}

func (m mockStakingKeeper) GetAllValidators(_ context.Context) ([]interface{}, error) {
	return nil, nil
}
func (m mockStakingKeeper) GetValidator(_ context.Context, _ sdk.ValAddress) (interface{}, error) {
	return nil, nil
}

// newTestKeeper creates a Keeper with in-memory stores suitable for testing
// query, upgrade, and genesis operations.
func newTestKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg) // registers math.Int, sdk.Coin, etc.
	cdc := codec.NewProtoCodec(reg)

	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)

	// Need to create a minimal seal keeper and verify keeper.
	// Since we only test pouw query/upgrade, we use the keeper constructor directly.
	// The seal and verify keepers are zero-valued (not called in query paths).
	k := newTestKeeperFromStore(cdc, storeService)

	// Initialize default params.
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	require.NoError(t, k.JobCount.Set(ctx, 0))

	return k, ctx
}

// newTestKeeperFromStore creates a Keeper using raw collections for test.
func newTestKeeperFromStore(cdc codec.Codec, storeService store.KVStoreService) keeper.Keeper {
	sb := collections.NewSchemaBuilder(storeService)

	k := keeper.Keeper{
		Jobs: collections.NewMap(
			sb,
			collections.NewPrefix(types.JobKeyPrefix),
			"jobs",
			collections.StringKey,
			codec.CollValue[types.ComputeJob](cdc),
		),
		PendingJobs: collections.NewMap(
			sb,
			collections.NewPrefix(types.PendingJobKeyPrefix),
			"pending_jobs",
			collections.StringKey,
			codec.CollValue[types.ComputeJob](cdc),
		),
		RegisteredModels: collections.NewMap(
			sb,
			collections.NewPrefix(types.ModelRegistryKeyPrefix),
			"registered_models",
			collections.StringKey,
			codec.CollValue[types.RegisteredModel](cdc),
		),
		ValidatorStats: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorStatsKeyPrefix),
			"validator_stats",
			collections.StringKey,
			codec.CollValue[types.ValidatorStats](cdc),
		),
		ValidatorCapabilities: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorCapabilitiesKeyPrefix),
			"validator_capabilities",
			collections.StringKey,
			codec.CollValue[types.ValidatorCapability](cdc),
		),
		ValidatorPCR0Mappings: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorPCR0KeyPrefix),
			"validator_pcr0_mappings",
			collections.StringKey,
			collections.StringValue,
		),
		RegisteredPCR0Set: collections.NewKeySet(
			sb,
			collections.NewPrefix(types.RegisteredPCR0KeyPrefix),
			"registered_pcr0_set",
			collections.StringKey,
		),
		ValidatorMeasurements: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorMeasurementKeyPrefix),
			"validator_measurements",
			collections.StringKey,
			collections.StringValue,
		),
		RegisteredMeasurements: collections.NewKeySet(
			sb,
			collections.NewPrefix(types.RegisteredMeasurementKeyPrefix),
			"registered_measurements_set",
			collections.StringKey,
		),
		JobCount: collections.NewItem(
			sb,
			collections.NewPrefix(types.JobCountKey),
			"job_count",
			collections.Uint64Value,
		),
		Params: collections.NewItem(
			sb,
			collections.NewPrefix(types.ParamsKey),
			"params",
			codec.CollValue[types.Params](cdc),
		),
	}

	return k
}

// seedJobs creates n test jobs in the keeper. Returns the IDs of created jobs.
// NOTE: Jobs are created without the Fee field to avoid proto v2/gogoproto
// serialization conflict (sdk.Coin embeds math.Int which is a gogoproto
// custom type and cannot be marshalled through the proto v2 path).
func seedJobs(t *testing.T, ctx sdk.Context, k keeper.Keeper, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		modelHash := sha256.Sum256([]byte(fmt.Sprintf("model-%d", i)))
		inputHash := sha256.Sum256([]byte(fmt.Sprintf("input-%d", i)))
		job := types.ComputeJob{
			Id:          fmt.Sprintf("job-%d", i),
			ModelHash:   modelHash[:],
			InputHash:   inputHash[:],
			RequestedBy: fmt.Sprintf("requester-%d", i),
			ProofType:   types.ProofTypeTEE,
			Purpose:     "test",
			Status:      types.JobStatusPending,
			BlockHeight: ctx.BlockHeight(),
			// Fee is intentionally nil to avoid math.Int serialization issue.
		}
		ids[i] = job.Id

		// Register the model first
		modelKey := fmt.Sprintf("%x", modelHash[:])
		_ = k.RegisteredModels.Set(ctx, modelKey, types.RegisteredModel{
			ModelHash: modelHash[:],
			ModelId:   fmt.Sprintf("model-%d", i),
			Name:      fmt.Sprintf("Test Model %d", i),
			Owner:     fmt.Sprintf("requester-%d", i),
		})

		require.NoError(t, k.Jobs.Set(ctx, job.Id, job))
		if job.Status == types.JobStatusPending {
			require.NoError(t, k.PendingJobs.Set(ctx, job.Id, job))
		}
	}

	count, _ := k.JobCount.Get(ctx)
	require.NoError(t, k.JobCount.Set(ctx, count+uint64(n)))

	return ids
}

// =============================================================================
// Section 1: Query Server Tests
// =============================================================================

func TestQueryServer_Job_Found(t *testing.T) {
	k, ctx := newTestKeeper(t)
	ids := seedJobs(t, ctx, k, 1)

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.Job(ctx, &types.QueryJobRequest{JobId: ids[0]})

	require.NoError(t, err)
	require.NotNil(t, resp.Job)
	require.Equal(t, ids[0], resp.Job.Id)
}

func TestQueryServer_Job_NotFound(t *testing.T) {
	k, ctx := newTestKeeper(t)

	qs := keeper.NewQueryServerImpl(k)
	_, err := qs.Job(ctx, &types.QueryJobRequest{JobId: "nonexistent"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestQueryServer_Job_EmptyID(t *testing.T) {
	k, ctx := newTestKeeper(t)

	qs := keeper.NewQueryServerImpl(k)
	_, err := qs.Job(ctx, &types.QueryJobRequest{JobId: ""})

	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestQueryServer_Jobs_ReturnsAll(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 5)

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.Jobs(ctx, &types.QueryJobsRequest{})

	require.NoError(t, err)
	require.Len(t, resp.Jobs, 5)
}

func TestQueryServer_Jobs_EmptySet(t *testing.T) {
	k, ctx := newTestKeeper(t)

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.Jobs(ctx, &types.QueryJobsRequest{})

	require.NoError(t, err)
	require.Empty(t, resp.Jobs)
}

func TestQueryServer_PendingJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 3)

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.PendingJobs(ctx, &types.QueryPendingJobsRequest{})

	require.NoError(t, err)
	require.Len(t, resp.Jobs, 3) // all newly created jobs are pending
}

func TestQueryServer_Params(t *testing.T) {
	k, ctx := newTestKeeper(t)

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.Params(ctx, &types.QueryParamsRequest{})

	require.NoError(t, err)
	require.NotNil(t, resp.Params)
	require.Equal(t, int64(3), resp.Params.MinValidators)
}

func TestQueryServer_ValidatorStats_Found(t *testing.T) {
	k, ctx := newTestKeeper(t)
	stats := types.NewValidatorStats("validator-1")
	stats.RecordSuccess(100)
	require.NoError(t, k.SetValidatorStats(ctx, stats))

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.ValidatorStats(ctx, &types.QueryValidatorStatsRequest{
		ValidatorAddress: "validator-1",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Stats)
	require.Equal(t, int64(1), resp.Stats.SuccessfulJobs)
}

func TestQueryServer_ValidatorStats_NotFound(t *testing.T) {
	k, ctx := newTestKeeper(t)

	qs := keeper.NewQueryServerImpl(k)
	_, err := qs.ValidatorStats(ctx, &types.QueryValidatorStatsRequest{
		ValidatorAddress: "nonexistent",
	})

	require.Error(t, err)
}

// =============================================================================
// Section 2: Upgrade & Migration Tests
// =============================================================================

func TestUpgrade_MigrateV1ToV2_BackfillsParams(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Set params with some missing fields.
	brokenParams := &types.Params{
		MinValidators: 0,  // should be backfilled
		BaseJobFee:    "", // should be backfilled
	}
	require.NoError(t, k.SetParams(ctx, brokenParams))

	err := keeper.RunMigrations(ctx, k, 1, 2)
	require.NoError(t, err)

	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	require.True(t, params.MinValidators > 0, "MinValidators should be backfilled")
	require.NotEmpty(t, params.BaseJobFee, "BaseJobFee should be backfilled")
}

func TestUpgrade_MigrateV1ToV2_CleansOrphanPendingJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 3)

	// Manually mark a job as completed but leave it in PendingJobs (orphan).
	job, err := k.Jobs.Get(ctx, "job-0")
	require.NoError(t, err)
	job.Status = types.JobStatusCompleted
	require.NoError(t, k.Jobs.Set(ctx, "job-0", job))
	// It's still in PendingJobs — orphan.

	err = keeper.RunMigrations(ctx, k, 1, 2)
	require.NoError(t, err)

	// The orphan should be removed from PendingJobs.
	hasPending, _ := k.PendingJobs.Has(ctx, "job-0")
	require.False(t, hasPending, "completed job should be removed from PendingJobs")
}

func TestUpgrade_MigrateV1ToV2_ReconcilesJobCount(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 5)

	// Deliberately set wrong count.
	require.NoError(t, k.JobCount.Set(ctx, 999))

	err := keeper.RunMigrations(ctx, k, 1, 2)
	require.NoError(t, err)

	count, err := k.JobCount.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(5), count, "job count should be reconciled to 5")
}

func TestUpgrade_MigrateV1ToV2_ClampsReputationScore(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Set a validator with out-of-range reputation.
	stats := types.ValidatorStats{
		ValidatorAddress: "validator-bad",
		ReputationScore:  200, // out of range
	}
	require.NoError(t, k.ValidatorStats.Set(ctx, stats.ValidatorAddress, stats))

	err := keeper.RunMigrations(ctx, k, 1, 2)
	require.NoError(t, err)

	fixedStats, err := k.ValidatorStats.Get(ctx, "validator-bad")
	require.NoError(t, err)
	require.Equal(t, int64(100), fixedStats.ReputationScore,
		"reputation should be clamped to 100")
}

func TestUpgrade_RunMigrations_NoOp(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Same version should be no-op.
	err := keeper.RunMigrations(ctx, k, 1, 1)
	require.NoError(t, err)
}

func TestUpgrade_PreUpgradeValidation_Clean(t *testing.T) {
	k, ctx := newTestKeeper(t)

	warnings := keeper.PreUpgradeValidation(ctx, k)
	require.Empty(t, warnings, "clean state should have no warnings")
}

func TestUpgrade_PreUpgradeValidation_PendingJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 3)

	warnings := keeper.PreUpgradeValidation(ctx, k)
	require.Len(t, warnings, 1, "should warn about pending jobs")
	require.Contains(t, warnings[0], "pending jobs")
}

func TestUpgrade_PreUpgradeValidation_AllowSimulated(t *testing.T) {
	k, ctx := newTestKeeper(t)
	params := types.DefaultParams()
	params.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, params))

	warnings := keeper.PreUpgradeValidation(ctx, k)
	found := false
	for _, w := range warnings {
		if w == "WARNING: AllowSimulated is true — this should be false on production chains before upgrade" {
			found = true
		}
	}
	require.True(t, found, "should warn about AllowSimulated")
}

func TestUpgrade_PostUpgradeValidation_Clean(t *testing.T) {
	k, ctx := newTestKeeper(t)

	err := keeper.PostUpgradeValidation(ctx, k)
	require.NoError(t, err)
}

func TestUpgrade_ModuleConsensusVersion(t *testing.T) {
	require.Equal(t, uint64(2), uint64(keeper.ModuleConsensusVersion),
		"current consensus version should be 2")
}

// =============================================================================
// Section 3: Genesis Round-Trip Tests
// =============================================================================

func TestGenesis_RoundTrip_Empty(t *testing.T) {
	k, ctx := newTestKeeper(t)

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)
	require.NotNil(t, exported.Params)
	require.Empty(t, exported.Jobs)

	// Re-initialize from export.
	k2, ctx2 := newTestKeeper(t)
	require.NoError(t, k2.InitGenesis(ctx2, exported))

	reExported, err := k2.ExportGenesis(ctx2)
	require.NoError(t, err)
	require.Equal(t, exported.Params.MinValidators, reExported.Params.MinValidators)
}

func TestGenesis_RoundTrip_WithJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 5)

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)
	require.Len(t, exported.Jobs, 5)

	// Re-initialize.
	k2, ctx2 := newTestKeeper(t)
	require.NoError(t, k2.InitGenesis(ctx2, exported))

	reExported, err := k2.ExportGenesis(ctx2)
	require.NoError(t, err)
	require.Len(t, reExported.Jobs, 5)
}

func TestGenesis_RoundTrip_WithValidatorStats(t *testing.T) {
	k, ctx := newTestKeeper(t)

	stats := types.NewValidatorStats("validator-1")
	stats.RecordSuccess(150)
	stats.RecordSuccess(200)
	stats.RecordFailure()
	require.NoError(t, k.SetValidatorStats(ctx, stats))

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)
	require.Len(t, exported.ValidatorStats, 1)
	require.Equal(t, int64(2), exported.ValidatorStats[0].SuccessfulJobs)
}

func TestGenesis_ParamsPreserved(t *testing.T) {
	k, ctx := newTestKeeper(t)
	customParams := types.DefaultParams()
	customParams.ConsensusThreshold = 80
	customParams.MaxJobsPerBlock = 50
	require.NoError(t, k.SetParams(ctx, customParams))

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(80), exported.Params.ConsensusThreshold)
	require.Equal(t, int64(50), exported.Params.MaxJobsPerBlock)
}

func TestGenesis_ExportJSON(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 2)

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)

	// Should be serializable to JSON.
	jsonBytes, err := json.Marshal(exported)
	require.NoError(t, err)
	require.Contains(t, string(jsonBytes), "job-0")
}

// =============================================================================
// Section 4: Load & Stress Tests
// =============================================================================

func TestLoad_ManyJobsSubmission(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	k, ctx := newTestKeeper(t)
	const jobCount = 1000

	start := time.Now()
	ids := seedJobs(t, ctx, k, jobCount)
	elapsed := time.Since(start)

	t.Logf("Created %d jobs in %v (%.1f jobs/s)", jobCount, elapsed, float64(jobCount)/elapsed.Seconds())

	require.Len(t, ids, jobCount)

	// Verify count.
	count, err := k.JobCount.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(jobCount), count)
}

func TestLoad_ManyValidatorStats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	k, ctx := newTestKeeper(t)
	const validatorCount = 200

	start := time.Now()
	for i := 0; i < validatorCount; i++ {
		stats := types.NewValidatorStats(fmt.Sprintf("validator-%d", i))
		for j := 0; j < 100; j++ {
			stats.RecordSuccess(int64(j * 10))
		}
		require.NoError(t, k.SetValidatorStats(ctx, stats))
	}
	elapsed := time.Since(start)

	t.Logf("Created %d validator stats in %v", validatorCount, elapsed)

	// Query all.
	queryStart := time.Now()
	count := 0
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, _ types.ValidatorStats) (bool, error) {
		count++
		return false, nil
	})
	queryElapsed := time.Since(queryStart)

	require.Equal(t, validatorCount, count)
	t.Logf("Queried %d validator stats in %v", count, queryElapsed)
}

func TestLoad_FeeBreakdownStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	config := keeper.DefaultFeeDistributionConfig()
	rng := rand.New(rand.NewSource(42))
	const iterations = 100000

	start := time.Now()
	for i := 0; i < iterations; i++ {
		amount := rng.Int63n(100000000) + 1
		validatorCount := int(rng.Int63n(20)) + 1
		fee := sdk.NewInt64Coin("uaeth", amount)
		result := keeper.CalculateFeeBreakdown(fee, config, validatorCount)

		// Quick conservation check.
		distributed := result.PerValidatorReward.Amount.MulRaw(int64(validatorCount)).
			Add(result.TreasuryAmount.Amount).
			Add(result.BurnedAmount.Amount).
			Add(result.InsuranceFund.Amount)
		if !distributed.Equal(fee.Amount) {
			t.Fatalf("conservation violated at iteration %d", i)
		}
	}
	elapsed := time.Since(start)

	t.Logf("Computed %d fee breakdowns in %v (%.0f ops/s)",
		iterations, elapsed, float64(iterations)/elapsed.Seconds())
}

func TestLoad_ValidateParamsStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	params := types.DefaultParams()
	const iterations = 100000

	start := time.Now()
	for i := 0; i < iterations; i++ {
		err := keeper.ValidateParams(params)
		if err != nil {
			t.Fatalf("unexpected validation error at iteration %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	t.Logf("Validated params %d times in %v (%.0f ops/s)",
		iterations, elapsed, float64(iterations)/elapsed.Seconds())
}

func TestLoad_MergeParamsStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	current := types.DefaultParams()
	rng := rand.New(rand.NewSource(42))
	const iterations = 100000

	start := time.Now()
	for i := 0; i < iterations; i++ {
		update := &types.Params{
			MinValidators:         rng.Int63n(100) + 1,
			ConsensusThreshold:    rng.Int63n(51) + 50,
			RequireTeeAttestation: rng.Intn(2) == 1,
			AllowZkmlFallback:     rng.Intn(2) == 1,
			AllowSimulated:        false,
		}
		merged := keeper.MergeParams(current, update)
		if merged == nil {
			t.Fatalf("nil merge result at iteration %d", i)
		}
	}
	elapsed := time.Since(start)

	t.Logf("Merged params %d times in %v (%.0f ops/s)",
		iterations, elapsed, float64(iterations)/elapsed.Seconds())
}

func TestLoad_DiffParamsStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	old := types.DefaultParams()
	rng := rand.New(rand.NewSource(42))
	const iterations = 100000

	start := time.Now()
	for i := 0; i < iterations; i++ {
		newParams := types.DefaultParams()
		newParams.MinValidators = rng.Int63n(100) + 1
		newParams.ConsensusThreshold = rng.Int63n(51) + 50
		newParams.BaseJobFee = fmt.Sprintf("%duaeth", rng.Int63n(10000)+1)

		changes := keeper.DiffParams(old, newParams)
		_ = changes
	}
	elapsed := time.Since(start)

	t.Logf("Diffed params %d times in %v (%.0f ops/s)",
		iterations, elapsed, float64(iterations)/elapsed.Seconds())
}

// =============================================================================
// Section 5: Additional Benchmarks
// =============================================================================

func BenchmarkQueryServer_Job(b *testing.B) {
	k, ctx := newBenchKeeper(b)
	seedJobsForBench(b, ctx, k, 100)

	qs := keeper.NewQueryServerImpl(k)
	req := &types.QueryJobRequest{JobId: "job-50"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qs.Job(ctx, req)
	}
}

func BenchmarkQueryServer_Jobs(b *testing.B) {
	k, ctx := newBenchKeeper(b)
	seedJobsForBench(b, ctx, k, 100)

	qs := keeper.NewQueryServerImpl(k)
	req := &types.QueryJobsRequest{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qs.Jobs(ctx, req)
	}
}

func BenchmarkQueryServer_Params(b *testing.B) {
	k, ctx := newBenchKeeper(b)
	qs := keeper.NewQueryServerImpl(k)
	req := &types.QueryParamsRequest{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qs.Params(ctx, req)
	}
}

func BenchmarkMergeParams(b *testing.B) {
	current := types.DefaultParams()
	update := &types.Params{
		ConsensusThreshold:    80,
		RequireTeeAttestation: true,
		AllowZkmlFallback:     true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = keeper.MergeParams(current, update)
	}
}

func BenchmarkDiffParams(b *testing.B) {
	old := types.DefaultParams()
	newP := types.DefaultParams()
	newP.MinValidators = 5
	newP.BaseJobFee = "5000uaeth"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = keeper.DiffParams(old, newP)
	}
}

func BenchmarkRewardScaleByReputation(b *testing.B) {
	reward := sdk.NewInt64Coin("uaeth", 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = keeper.RewardScaleByReputation(reward, 75)
	}
}

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

func newBenchKeeper(b *testing.B) (keeper.Keeper, sdk.Context) {
	b.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	if err := cms.LoadLatestVersion(); err != nil {
		b.Fatal(err)
	}

	header := tmproto.Header{
		ChainID: "aethelred-bench-1",
		Height:  100,
		Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg) // registers math.Int, sdk.Coin, etc.
	cdc := codec.NewProtoCodec(reg)

	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)
	k := newTestKeeperFromStore(cdc, storeService)

	if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
		b.Fatal(err)
	}
	if err := k.JobCount.Set(ctx, 0); err != nil {
		b.Fatal(err)
	}

	return k, ctx
}

func seedJobsForBench(b *testing.B, ctx sdk.Context, k keeper.Keeper, n int) {
	b.Helper()
	for i := 0; i < n; i++ {
		modelHash := sha256.Sum256([]byte(fmt.Sprintf("model-%d", i)))
		inputHash := sha256.Sum256([]byte(fmt.Sprintf("input-%d", i)))
		job := types.ComputeJob{
			Id:          fmt.Sprintf("job-%d", i),
			ModelHash:   modelHash[:],
			InputHash:   inputHash[:],
			RequestedBy: fmt.Sprintf("requester-%d", i),
			ProofType:   types.ProofTypeTEE,
			Purpose:     "bench",
			Status:      types.JobStatusPending,
			BlockHeight: ctx.BlockHeight(),
		}
		if err := k.Jobs.Set(ctx, job.Id, job); err != nil {
			b.Fatal(err)
		}
	}
	if err := k.JobCount.Set(ctx, uint64(n)); err != nil {
		b.Fatal(err)
	}
}

// Ensure unused imports are valid.
var (
	_ = sdkmath.ZeroInt
	_ = collections.StringKey
)

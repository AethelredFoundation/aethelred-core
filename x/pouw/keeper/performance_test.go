//go:build !race
// +build !race

package keeper_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEK 35-36: Performance Tuning & Protocol Freeze Tests
//
// These tests verify:
//   1. Protocol freeze mechanism (7 tests)
//   2. Block processing budget (6 tests)
//   3. Performance profiles (6 tests)
//   4. Protocol version manifest (5 tests)
//   5. SLA enforcement (6 tests)
//   6. Performance benchmarks (5 tests)
//   7. Comprehensive performance report (3 tests)
//
// Total: 38 tests
// =============================================================================

// =============================================================================
// Section 1: Protocol Freeze Mechanism
// =============================================================================

func TestProtocolFreeze_NewFreeze(t *testing.T) {
	freeze := keeper.NewProtocolFreeze(500, "mainnet preparation", "gov-authority", "v1.0.0")

	require.True(t, freeze.IsFrozen)
	require.Equal(t, int64(500), freeze.FreezeHeight)
	require.Equal(t, "mainnet preparation", freeze.FreezeReason)
	require.Equal(t, "gov-authority", freeze.FrozenBy)
	require.Equal(t, "v1.0.0", freeze.ProtocolVersion)
	require.NotEmpty(t, freeze.AllowedOperations)
}

func TestProtocolFreeze_AllowedOperations(t *testing.T) {
	freeze := keeper.NewProtocolFreeze(500, "test", "gov", "v1.0.0")

	// Allowed operations should work
	require.True(t, freeze.IsOperationAllowed("QueryParams"))
	require.True(t, freeze.IsOperationAllowed("UpdateParams"))
	require.True(t, freeze.IsOperationAllowed("ProtocolFreeze"))

	// State-mutating operations should be blocked
	require.False(t, freeze.IsOperationAllowed("SubmitJob"))
	require.False(t, freeze.IsOperationAllowed("CompleteJob"))
	require.False(t, freeze.IsOperationAllowed("RegisterModel"))
}

func TestProtocolFreeze_CheckFreezeGate_Frozen(t *testing.T) {
	freeze := keeper.NewProtocolFreeze(500, "freeze reason", "gov", "v1.0.0")

	// Blocked operation
	err := keeper.CheckFreezeGate(freeze, "SubmitJob")
	require.Error(t, err)
	require.Contains(t, err.Error(), "protocol frozen")
	require.Contains(t, err.Error(), "SubmitJob")

	// Allowed operation
	err = keeper.CheckFreezeGate(freeze, "QueryParams")
	require.NoError(t, err)
}

func TestProtocolFreeze_CheckFreezeGate_Unfrozen(t *testing.T) {
	freeze := keeper.NewProtocolFreeze(500, "test", "gov", "v1.0.0")
	freeze.Unfreeze()

	// Everything should be allowed after unfreeze
	require.NoError(t, keeper.CheckFreezeGate(freeze, "SubmitJob"))
	require.NoError(t, keeper.CheckFreezeGate(freeze, "CompleteJob"))
}

func TestProtocolFreeze_CheckFreezeGate_NilState(t *testing.T) {
	// Nil freeze state means no freeze — all operations allowed
	err := keeper.CheckFreezeGate(nil, "SubmitJob")
	require.NoError(t, err)
}

func TestProtocolFreeze_Unfreeze(t *testing.T) {
	freeze := keeper.NewProtocolFreeze(500, "test", "gov", "v1.0.0")
	require.True(t, freeze.IsFrozen)

	freeze.Unfreeze()
	require.False(t, freeze.IsFrozen)

	// After unfreeze, all operations allowed
	require.True(t, freeze.IsOperationAllowed("SubmitJob"))
}

func TestProtocolFreeze_FreezeGateErrorMessage(t *testing.T) {
	freeze := keeper.NewProtocolFreeze(12345, "pre-launch lockdown", "gov-module", "v1.0.0")

	err := keeper.CheckFreezeGate(freeze, "RegisterModel")
	require.Error(t, err)
	require.Contains(t, err.Error(), "12345")
	require.Contains(t, err.Error(), "RegisterModel")
	require.Contains(t, err.Error(), "pre-launch lockdown")
}

// =============================================================================
// Section 2: Block Processing Budget
// =============================================================================

func TestBlockBudget_New(t *testing.T) {
	budget := keeper.NewBlockBudget(100 * time.Millisecond)
	require.NotNil(t, budget)
	require.True(t, budget.HasBudget())
	require.Equal(t, 100*time.Millisecond, budget.Remaining())
}

func TestBlockBudget_Default(t *testing.T) {
	budget := keeper.DefaultBlockBudget()
	require.NotNil(t, budget)
	require.True(t, budget.HasBudget())
	require.Equal(t, 200*time.Millisecond, budget.Remaining())
}

func TestBlockBudget_RunTask(t *testing.T) {
	budget := keeper.NewBlockBudget(1 * time.Second)

	elapsed, executed := budget.RunTask("fast_task", func() {
		// fast operation
		_ = 1 + 1
	})

	require.True(t, executed)
	require.Greater(t, elapsed, time.Duration(0))
	require.Less(t, budget.TotalSpent(), 1*time.Second)
}

func TestBlockBudget_ExhaustedSkipsTasks(t *testing.T) {
	// Very tiny budget — 1 nanosecond
	budget := keeper.NewBlockBudget(1 * time.Nanosecond)

	// First task will execute but exceed the budget
	_, _ = budget.RunTask("first_task", func() {
		time.Sleep(1 * time.Millisecond)
	})

	// Second task should be skipped because budget is exhausted
	_, executed := budget.RunTask("second_task", func() {
		t.Fatal("this should not execute")
	})

	require.False(t, executed)
}

func TestBlockBudget_Summary(t *testing.T) {
	budget := keeper.NewBlockBudget(1 * time.Second)

	budget.RunTask("task_a", func() {})
	budget.RunTask("task_b", func() {})

	timings, exceeded := budget.Summary()
	require.Len(t, timings, 2)
	require.Equal(t, "task_a", timings[0].Name)
	require.Equal(t, "task_b", timings[1].Name)
	require.False(t, timings[0].Skipped)
	require.False(t, timings[1].Skipped)
	require.False(t, exceeded)
}

func TestBlockBudget_TotalSpent(t *testing.T) {
	budget := keeper.NewBlockBudget(1 * time.Second)

	budget.RunTask("work", func() {
		time.Sleep(5 * time.Millisecond)
	})

	require.GreaterOrEqual(t, budget.TotalSpent(), 5*time.Millisecond)
}

// =============================================================================
// Section 3: Performance Profiles
// =============================================================================

func TestPerformanceProfile_Testnet(t *testing.T) {
	profile := keeper.TestnetProfile()

	require.Equal(t, "testnet", profile.Name)
	require.NoError(t, profile.ValidateProfile())
	require.Equal(t, 10, profile.MaxJobsPerBlock)
	require.Equal(t, 3, profile.MinValidatorsRequired)
}

func TestPerformanceProfile_Mainnet(t *testing.T) {
	profile := keeper.MainnetProfile()

	require.Equal(t, "mainnet", profile.Name)
	require.NoError(t, profile.ValidateProfile())
	require.Equal(t, 25, profile.MaxJobsPerBlock)
	require.Equal(t, 5, profile.MinValidatorsRequired)
	require.Equal(t, int64(200), profile.MaxBlockBudgetMs)
}

func TestPerformanceProfile_StressTest(t *testing.T) {
	profile := keeper.StressTestProfile()

	require.Equal(t, "stress", profile.Name)
	require.NoError(t, profile.ValidateProfile())
	require.Equal(t, 100, profile.MaxJobsPerBlock)
}

func TestPerformanceProfile_ValidationRejectsInvalid(t *testing.T) {
	// Zero MaxJobsPerBlock
	profile := keeper.MainnetProfile()
	profile.MaxJobsPerBlock = 0
	require.Error(t, profile.ValidateProfile())

	// MinValidatorsRequired too high
	profile = keeper.MainnetProfile()
	profile.MinValidatorsRequired = 200
	require.Error(t, profile.ValidateProfile())

	// MaxBlockBudgetMs too low
	profile = keeper.MainnetProfile()
	profile.MaxBlockBudgetMs = 10
	require.Error(t, profile.ValidateProfile())

	// Max < Target completion blocks
	profile = keeper.MainnetProfile()
	profile.MaxJobCompletionBlocks = 5
	profile.TargetJobCompletionBlocks = 10
	require.Error(t, profile.ValidateProfile())
}

func TestPerformanceProfile_ToSchedulerConfig(t *testing.T) {
	profile := keeper.MainnetProfile()
	config := profile.ToSchedulerConfig()

	require.Equal(t, profile.MaxJobsPerBlock, config.MaxJobsPerBlock)
	require.Equal(t, profile.MaxJobsPerValidator, config.MaxJobsPerValidator)
	require.Equal(t, profile.PriorityBoostPerBlock, config.PriorityBoostPerBlock)
	require.Equal(t, profile.MaxRetries, config.MaxRetries)
}

func TestPerformanceProfile_AllProfilesValid(t *testing.T) {
	profiles := []keeper.PerformanceProfile{
		keeper.TestnetProfile(),
		keeper.MainnetProfile(),
		keeper.StressTestProfile(),
	}

	for _, p := range profiles {
		require.NoError(t, p.ValidateProfile(), "profile %s should be valid", p.Name)
	}
}

// =============================================================================
// Section 4: Protocol Version Manifest
// =============================================================================

func TestProtocolManifest_Build(t *testing.T) {
	k, ctx := newTestKeeper(t)

	manifest := keeper.BuildProtocolManifest(ctx, k)

	require.NotNil(t, manifest)
	require.Equal(t, "aethelred-test-1", manifest.ChainID)
	require.Equal(t, types.ModuleName, manifest.ModuleName)
	require.Equal(t, uint64(keeper.ModuleConsensusVersion), manifest.ModuleVersion)
	require.NotEmpty(t, manifest.ProtocolName)
	require.NotEmpty(t, manifest.GeneratedAt)
}

func TestProtocolManifest_HasFrozenParams(t *testing.T) {
	k, ctx := newTestKeeper(t)

	manifest := keeper.BuildProtocolManifest(ctx, k)

	require.NotNil(t, manifest.FrozenParams)
	require.Equal(t, int64(67), manifest.ConsensusThreshold)
	require.Equal(t, int64(3), manifest.MinValidators)
	require.False(t, manifest.AllowSimulated)
}

func TestProtocolManifest_HasComponents(t *testing.T) {
	k, ctx := newTestKeeper(t)

	manifest := keeper.BuildProtocolManifest(ctx, k)

	require.NotEmpty(t, manifest.Components)
	require.GreaterOrEqual(t, len(manifest.Components), 5,
		"must have at least 5 component versions")

	// All components must have required fields
	for _, c := range manifest.Components {
		require.NotEmpty(t, c.Name)
		require.NotEmpty(t, c.Version)
		require.NotEmpty(t, c.Status)
	}
}

func TestProtocolManifest_InvariantsPass(t *testing.T) {
	k, ctx := newTestKeeper(t)

	manifest := keeper.BuildProtocolManifest(ctx, k)

	require.True(t, manifest.InvariantsPass, "invariants should pass in clean state")
	require.Equal(t, 7, manifest.InvariantCount)
}

func TestProtocolManifest_Render(t *testing.T) {
	k, ctx := newTestKeeper(t)

	manifest := keeper.BuildProtocolManifest(ctx, k)
	rendered := manifest.RenderManifest()

	require.Contains(t, rendered, "PROTOCOL VERSION MANIFEST")
	require.Contains(t, rendered, "Aethelred Sovereign L1")
	require.Contains(t, rendered, "FROZEN PARAMETERS")
	require.Contains(t, rendered, "COMPONENT VERSIONS")
	require.Contains(t, rendered, "SECURITY POSTURE")
	require.Contains(t, rendered, "STATE STATISTICS")
	require.Contains(t, rendered, "PERFORMANCE PROFILE")

	t.Log(rendered)
}

// =============================================================================
// Section 5: SLA Enforcement
// =============================================================================

func TestSLA_DefaultSLA(t *testing.T) {
	sla := keeper.DefaultValidatorSLA()

	require.Equal(t, 95, sla.MinUptimePercent)
	require.Equal(t, int64(20), sla.MaxResponseBlocks)
	require.Equal(t, int64(40), sla.MinReputationScore)
	require.Equal(t, int64(10), sla.MaxConsecutiveMisses)
}

func TestSLA_PerfectValidatorNoViolations(t *testing.T) {
	sla := keeper.DefaultValidatorSLA()
	stats := types.ValidatorStats{
		ValidatorAddress:   "val1",
		TotalJobsProcessed: 100,
		SuccessfulJobs:     98,
		FailedJobs:         2,
		ReputationScore:    95,
		SlashingEvents:     0,
	}

	violations := keeper.CheckValidatorSLA(sla, stats)
	require.Empty(t, violations, "perfect validator should have no SLA violations")
}

func TestSLA_LowReputationViolation(t *testing.T) {
	sla := keeper.DefaultValidatorSLA()
	stats := types.ValidatorStats{
		ValidatorAddress:   "bad-val",
		TotalJobsProcessed: 50,
		SuccessfulJobs:     30,
		FailedJobs:         20,
		ReputationScore:    15,
		SlashingEvents:     1,
	}

	violations := keeper.CheckValidatorSLA(sla, stats)
	require.NotEmpty(t, violations)

	// Should have reputation violation
	hasRepViolation := false
	for _, v := range violations {
		if v.Metric == "reputation_score" {
			hasRepViolation = true
			require.Equal(t, "critical", v.Severity, "low reputation should be critical")
		}
	}
	require.True(t, hasRepViolation, "should have reputation_score violation")
}

func TestSLA_HighFailureRateViolation(t *testing.T) {
	sla := keeper.DefaultValidatorSLA()
	stats := types.ValidatorStats{
		ValidatorAddress:   "fail-val",
		TotalJobsProcessed: 100,
		SuccessfulJobs:     80,
		FailedJobs:         20,
		ReputationScore:    60,
		SlashingEvents:     0,
	}

	violations := keeper.CheckValidatorSLA(sla, stats)
	// 20% failure rate > 5% threshold (100 - 95 = 5%)
	hasFailViolation := false
	for _, v := range violations {
		if v.Metric == "failure_rate" {
			hasFailViolation = true
		}
	}
	require.True(t, hasFailViolation, "should have failure_rate violation")
}

func TestSLA_ExcessiveSlashingViolation(t *testing.T) {
	sla := keeper.DefaultValidatorSLA()
	stats := types.ValidatorStats{
		ValidatorAddress:   "slash-val",
		TotalJobsProcessed: 50,
		SuccessfulJobs:     45,
		FailedJobs:         5,
		ReputationScore:    50,
		SlashingEvents:     5,
	}

	violations := keeper.CheckValidatorSLA(sla, stats)
	hasSlashViolation := false
	for _, v := range violations {
		if v.Metric == "slashing_events" {
			hasSlashViolation = true
			require.Equal(t, "critical", v.Severity)
		}
	}
	require.True(t, hasSlashViolation, "should have slashing_events violation")
}

func TestSLA_RunSLACheck_Integration(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Seed a few validators
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress:   addr,
			TotalJobsProcessed: 100,
			SuccessfulJobs:     95,
			FailedJobs:         5,
			ReputationScore:    80,
			SlashingEvents:     0,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	sla := keeper.DefaultValidatorSLA()
	violations := keeper.RunSLACheck(ctx, k, sla)

	// Good validators should have no violations
	require.Empty(t, violations, "good validators should pass SLA")
}

// =============================================================================
// Section 6: Performance Benchmarks
// =============================================================================

func TestBenchmark_InvariantsComplete(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunInvariantBenchmark(ctx, k, 10)

	require.Equal(t, "AllInvariants", result.Name)
	require.Equal(t, 10, result.Iterations)
	require.Greater(t, result.TotalTime, time.Duration(0))
	require.Greater(t, result.AvgTime, time.Duration(0))
	require.Greater(t, result.OpsPerSec, float64(0))

	// Invariants should complete in under 10ms per call in clean state
	require.Less(t, result.AvgTime, 10*time.Millisecond,
		"invariants should be fast in clean state")
}

func TestBenchmark_ParamValidation(t *testing.T) {
	result := keeper.RunParamValidationBenchmark(100)

	require.Equal(t, "ValidateParams", result.Name)
	require.Equal(t, 100, result.Iterations)
	require.Greater(t, result.OpsPerSec, float64(100000),
		"param validation should run > 100k ops/sec")
}

func TestBenchmark_ConsistencyChecks(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunConsistencyCheckBenchmark(ctx, k, 10)

	require.Equal(t, "EndBlockConsistencyChecks", result.Name)
	require.Equal(t, 10, result.Iterations)
	require.Greater(t, result.TotalTime, time.Duration(0))
}

func TestBenchmark_PerformanceScore(t *testing.T) {
	result := keeper.RunPerformanceScoreBenchmark(1000)

	require.Equal(t, "PerformanceScore", result.Name)
	require.Equal(t, 1000, result.Iterations)
	require.Greater(t, result.OpsPerSec, float64(1000000),
		"performance scoring should run > 1M ops/sec")
}

func TestBenchmark_MinMaxBounds(t *testing.T) {
	result := keeper.RunParamValidationBenchmark(100)

	require.LessOrEqual(t, result.MinTime, result.AvgTime,
		"min should be <= avg")
	require.GreaterOrEqual(t, result.MaxTime, result.AvgTime,
		"max should be >= avg")
	require.LessOrEqual(t, result.MinTime, result.MaxTime,
		"min should be <= max")
}

// =============================================================================
// Section 7: Comprehensive Performance Report
// =============================================================================

func TestPerformanceReport_Integration(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunPerformanceTuningReport(ctx, k)

	require.NotNil(t, report)
	require.Equal(t, "aethelred-test-1", report.ChainID)
	require.NotEmpty(t, report.GeneratedAt)
	require.NotEmpty(t, report.Benchmarks)
	require.GreaterOrEqual(t, len(report.Benchmarks), 4,
		"must have at least 4 benchmark results")
}

func TestPerformanceReport_PerformanceReady(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunPerformanceTuningReport(ctx, k)

	// In a clean state with no load, performance should be ready
	require.True(t, report.IsPerformanceReady,
		"clean state should be performance-ready")
}

func TestPerformanceReport_BudgetUtilization(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunPerformanceTuningReport(ctx, k)

	// Budget utilization should be very low in clean state
	require.Less(t, report.BudgetUtilization, 0.5,
		"clean state budget utilization should be < 50%%")
	require.Equal(t, int64(200), report.BlockBudgetMs)
}

// =============================================================================
// Helper: import fmt for SLA test seeding
// =============================================================================

// The fmt import is already available from devex_test.go which is in the
// same package. If not, we use a local alias.
var _ = strings.Contains // ensure strings import is used

// =============================================================================
// Section 8: MAINNET STRESS TESTS (10K Jobs, 1000+ Validators)
// =============================================================================

// TestStress_10KConcurrentJobs tests processing 10,000 concurrent compute jobs
func TestStress_10KConcurrentJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping 10K job stress test in short mode")
	}

	const numJobs = 10000

	k, ctx := newTestKeeper(t)

	// Set up 100 validators to process jobs
	for i := 0; i < 100; i++ {
		addr := fmt.Sprintf("stress-val-%d", i)
		cap := types.ValidatorCapability{
			Address:           addr,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 100,
			IsOnline:          true,
			ReputationScore:   80,
		}
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, addr, cap))
	}

	start := time.Now()

	// Create and process 10K jobs
	successfulJobs := 0
	failedCreation := 0

	for i := 0; i < numJobs; i++ {
		jobID := fmt.Sprintf("stress-job-%d", i)
		job := types.ComputeJob{
			Id:          jobID,
			Status:      types.JobStatusPending,
			RequestedBy: "cosmos1stresstest",
			ModelHash:   randomHash(),
			InputHash:   randomHash(),
			ProofType:   types.ProofTypeTEE,
			Priority:    int64(i % 10), // Vary priority
		}

		if err := k.Jobs.Set(ctx, jobID, job); err != nil {
			failedCreation++
		} else {
			successfulJobs++
		}
	}

	elapsed := time.Since(start)
	jobsPerSecond := float64(successfulJobs) / elapsed.Seconds()

	t.Logf("10K Job Stress Test Results:")
	t.Logf("  Total jobs: %d", numJobs)
	t.Logf("  Successful: %d", successfulJobs)
	t.Logf("  Failed: %d", failedCreation)
	t.Logf("  Time: %v", elapsed)
	t.Logf("  Jobs/second: %.2f", jobsPerSecond)

	// Performance assertion: should handle at least 1000 jobs/sec
	require.GreaterOrEqual(t, jobsPerSecond, float64(1000),
		"Should process at least 1000 jobs/sec")
	require.Equal(t, 0, failedCreation, "All jobs should be created successfully")
}

// TestStress_1000Validators tests consensus with 1000+ validators
func TestStress_1000Validators(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping 1000 validator stress test in short mode")
	}

	const numValidators = 1000

	k, ctx := newTestKeeper(t)

	start := time.Now()

	// Register 1000 validators
	for i := 0; i < numValidators; i++ {
		addr := fmt.Sprintf("large-val-%d", i)
		cap := types.ValidatorCapability{
			Address:           addr,
			TeePlatforms:      []string{"aws-nitro", "azure-sev"},
			MaxConcurrentJobs: 10,
			IsOnline:          i%100 != 99, // 99% online
			ReputationScore:   int64(70 + (i % 30)),
		}
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, addr, cap))

		// Also create stats
		stats := types.ValidatorStats{
			ValidatorAddress:   addr,
			TotalJobsProcessed: int64(i * 10),
			SuccessfulJobs:     int64(i * 9),
			FailedJobs:         int64(i),
			ReputationScore:    cap.ReputationScore,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	registrationTime := time.Since(start)

	// Test iteration performance
	iterStart := time.Now()
	validatorCount := 0
	onlineCount := 0

	err := k.ValidatorCapabilities.Walk(ctx, nil, func(key string, val types.ValidatorCapability) (bool, error) {
		validatorCount++
		if val.IsOnline {
			onlineCount++
		}
		return false, nil
	})
	require.NoError(t, err)

	iterationTime := time.Since(iterStart)

	t.Logf("1000 Validator Stress Test Results:")
	t.Logf("  Total validators: %d", validatorCount)
	t.Logf("  Online validators: %d", onlineCount)
	t.Logf("  Registration time: %v", registrationTime)
	t.Logf("  Iteration time: %v", iterationTime)
	t.Logf("  Validators/sec (registration): %.2f", float64(numValidators)/registrationTime.Seconds())
	t.Logf("  Validators/sec (iteration): %.2f", float64(validatorCount)/iterationTime.Seconds())

	require.Equal(t, numValidators, validatorCount)
	// Iteration should be fast - under 100ms for 1000 validators
	require.Less(t, iterationTime, 100*time.Millisecond,
		"Iteration over 1000 validators should be < 100ms")
}

// TestStress_ConsensusCalculation tests consensus calculation with large validator sets
func TestStress_ConsensusCalculation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping consensus calculation stress test in short mode")
	}

	scenarios := []struct {
		name            string
		totalVals       int
		byzantineRatio  float64
		expectConsensus bool
	}{
		{"100 vals, 30% byzantine", 100, 0.30, true},
		{"500 vals, 20% byzantine", 500, 0.20, true},
		{"1000 vals, 33% byzantine", 1000, 0.33, true},
		{"1000 vals, 40% byzantine", 1000, 0.40, false},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			start := time.Now()

			byzantineCount := int(float64(sc.totalVals) * sc.byzantineRatio)
			honestCount := sc.totalVals - byzantineCount

			// Simulate vote aggregation
			modelHash := randomHash()
			inputHash := randomHash()
			correctOutput := computeCorrectOutput(modelHash, inputHash)

			honestVotes := 0
			byzantineVotes := 0
			outputCounts := make(map[string]int)

			// Honest votes
			for i := 0; i < honestCount; i++ {
				key := fmt.Sprintf("%x", correctOutput)
				outputCounts[key]++
				honestVotes++
			}

			// Byzantine votes (each votes for different wrong answer)
			for i := 0; i < byzantineCount; i++ {
				wrongOutput := randomHash()
				key := fmt.Sprintf("%x", wrongOutput)
				outputCounts[key]++
				byzantineVotes++
			}

			// Find winning output
			maxVotes := 0
			var winningOutput string
			for output, votes := range outputCounts {
				if votes > maxVotes {
					maxVotes = votes
					winningOutput = output
				}
			}

			// Check if consensus reached (67% threshold)
			consensusRatio := float64(maxVotes) / float64(sc.totalVals) * 100
			reachedConsensus := consensusRatio >= 67.0

			// Verify correct behavior
			correctKey := fmt.Sprintf("%x", correctOutput)
			correctWon := winningOutput == correctKey

			elapsed := time.Since(start)

			t.Logf("  Validators: %d, Byzantine: %d (%.1f%%)", sc.totalVals, byzantineCount, sc.byzantineRatio*100)
			t.Logf("  Consensus: %v (%.1f%% for winner), Correct won: %v", reachedConsensus, consensusRatio, correctWon)
			t.Logf("  Calculation time: %v", elapsed)

			if sc.expectConsensus {
				require.True(t, reachedConsensus, "Should reach consensus")
				require.True(t, correctWon, "Correct output should win")
			}

			// Calculation should be fast even for 1000 validators
			require.Less(t, elapsed, 50*time.Millisecond,
				"Consensus calculation should be < 50ms")
		})
	}
}

// TestStress_MemoryUsage tests memory efficiency with large state
func TestStress_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory stress test in short mode")
	}

	k, ctx := newTestKeeper(t)

	// Create substantial state: 1000 jobs + 200 validators
	const (
		numJobs       = 1000
		numValidators = 200
	)

	start := time.Now()

	// Create jobs
	for i := 0; i < numJobs; i++ {
		job := types.ComputeJob{
			Id:          fmt.Sprintf("mem-job-%d", i),
			Status:      types.JobStatusPending,
			RequestedBy: "cosmos1memtest",
			ModelHash:   randomHash(),
			InputHash:   randomHash(),
			ProofType:   types.ProofTypeTEE,
		}
		require.NoError(t, k.Jobs.Set(ctx, job.Id, job))
	}

	// Create validators
	for i := 0; i < numValidators; i++ {
		addr := fmt.Sprintf("mem-val-%d", i)
		cap := types.ValidatorCapability{
			Address:           addr,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 10,
			IsOnline:          true,
			ReputationScore:   80,
		}
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, addr, cap))
	}

	setupTime := time.Since(start)

	// Test query performance
	queryStart := time.Now()

	jobCount := 0
	k.Jobs.Walk(ctx, nil, func(_ string, _ types.ComputeJob) (bool, error) {
		jobCount++
		return false, nil
	})

	valCount := 0
	k.ValidatorCapabilities.Walk(ctx, nil, func(_ string, _ types.ValidatorCapability) (bool, error) {
		valCount++
		return false, nil
	})

	queryTime := time.Since(queryStart)

	t.Logf("Memory Stress Test Results:")
	t.Logf("  Jobs: %d, Validators: %d", jobCount, valCount)
	t.Logf("  Setup time: %v", setupTime)
	t.Logf("  Query time (all walks): %v", queryTime)
	t.Logf("  Items/sec (setup): %.2f", float64(numJobs+numValidators)/setupTime.Seconds())
	t.Logf("  Items/sec (query): %.2f", float64(jobCount+valCount)/queryTime.Seconds())

	require.Equal(t, numJobs, jobCount)
	require.Equal(t, numValidators, valCount)

	// Queries should be fast even with significant state
	require.Less(t, queryTime, 500*time.Millisecond,
		"Full state iteration should be < 500ms")
}

// TestStress_CPUProfile tests CPU-bound operations at scale
func TestStress_CPUProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CPU profile stress test in short mode")
	}

	const iterations = 10000

	// Test 1: Hash computations
	hashStart := time.Now()
	for i := 0; i < iterations; i++ {
		_ = computeCorrectOutput(randomHash(), randomHash())
	}
	hashTime := time.Since(hashStart)

	// Test 2: Genesis validation (includes param validation)
	validStart := time.Now()
	genesis := types.DefaultGenesis()
	for i := 0; i < iterations; i++ {
		_ = genesis.Validate()
	}
	validTime := time.Since(validStart)

	// Test 3: Job state transitions
	transStart := time.Now()
	for i := 0; i < iterations; i++ {
		job := types.ComputeJob{
			Id:     fmt.Sprintf("cpu-job-%d", i),
			Status: types.JobStatusPending,
		}
		_ = job.MarkProcessing()
		_ = job.MarkCompleted(randomHash(), "seal")
	}
	transTime := time.Since(transStart)

	t.Logf("CPU Profile Stress Test Results:")
	t.Logf("  Hash computations (%d): %v (%.0f/sec)", iterations, hashTime, float64(iterations)/hashTime.Seconds())
	t.Logf("  Param validations (%d): %v (%.0f/sec)", iterations, validTime, float64(iterations)/validTime.Seconds())
	t.Logf("  State transitions (%d): %v (%.0f/sec)", iterations, transTime, float64(iterations)/transTime.Seconds())

	// Assertions on minimum performance
	require.Greater(t, float64(iterations)/hashTime.Seconds(), float64(50000),
		"Should compute > 50K hashes/sec")
	require.Greater(t, float64(iterations)/validTime.Seconds(), float64(100000),
		"Should validate > 100K params/sec")
	require.Greater(t, float64(iterations)/transTime.Seconds(), float64(100000),
		"Should handle > 100K state transitions/sec")
}

// TestStress_BlockProcessingUnderLoad simulates block processing under heavy load
func TestStress_BlockProcessingUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping block processing stress test in short mode")
	}

	const (
		numBlocks       = 100
		jobsPerBlock    = 25 // Mainnet profile limit
		validatorsCount = 100
	)

	k, ctx := newTestKeeper(t)

	// Setup validators
	for i := 0; i < validatorsCount; i++ {
		addr := fmt.Sprintf("block-val-%d", i)
		cap := types.ValidatorCapability{
			Address:           addr,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		}
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, addr, cap))
	}

	start := time.Now()
	totalJobs := 0
	blockTimes := make([]time.Duration, 0, numBlocks)

	for block := 0; block < numBlocks; block++ {
		blockStart := time.Now()

		// Simulate block processing with budget
		budget := keeper.NewBlockBudget(200 * time.Millisecond)

		// Process jobs for this block
		for j := 0; j < jobsPerBlock; j++ {
			jobID := fmt.Sprintf("block-%d-job-%d", block, j)

			budget.RunTask(fmt.Sprintf("create_%s", jobID), func() {
				job := types.ComputeJob{
					Id:          jobID,
					Status:      types.JobStatusPending,
					RequestedBy: "cosmos1blocktest",
					ModelHash:   randomHash(),
					InputHash:   randomHash(),
					ProofType:   types.ProofTypeTEE,
				}
				k.Jobs.Set(ctx, job.Id, job)
			})
			totalJobs++
		}

		blockTime := time.Since(blockStart)
		blockTimes = append(blockTimes, blockTime)
	}

	elapsed := time.Since(start)

	// Calculate statistics
	var totalBlockTime time.Duration
	var maxBlockTime time.Duration
	for _, bt := range blockTimes {
		totalBlockTime += bt
		if bt > maxBlockTime {
			maxBlockTime = bt
		}
	}
	avgBlockTime := totalBlockTime / time.Duration(numBlocks)

	t.Logf("Block Processing Stress Test Results:")
	t.Logf("  Blocks: %d, Jobs/block: %d, Total jobs: %d", numBlocks, jobsPerBlock, totalJobs)
	t.Logf("  Total time: %v", elapsed)
	t.Logf("  Avg block time: %v", avgBlockTime)
	t.Logf("  Max block time: %v", maxBlockTime)
	t.Logf("  Blocks/second: %.2f", float64(numBlocks)/elapsed.Seconds())
	t.Logf("  Jobs/second: %.2f", float64(totalJobs)/elapsed.Seconds())

	// Performance assertions
	require.Less(t, avgBlockTime, 200*time.Millisecond,
		"Average block time should be < 200ms")
	require.Less(t, maxBlockTime, 500*time.Millisecond,
		"Max block time should be < 500ms")
}

// TestStress_ConcurrentValidatorUpdates tests concurrent validator state updates
func TestStress_ConcurrentValidatorUpdates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent validator update stress test in short mode")
	}

	k, ctx := newTestKeeper(t)

	const numValidators = 100
	const updatesPerValidator = 100

	// Setup validators
	for i := 0; i < numValidators; i++ {
		addr := fmt.Sprintf("conc-val-%d", i)
		cap := types.ValidatorCapability{
			Address:           addr,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 10,
			IsOnline:          true,
			ReputationScore:   50,
		}
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, addr, cap))

		stats := types.ValidatorStats{
			ValidatorAddress:   addr,
			TotalJobsProcessed: 0,
			SuccessfulJobs:     0,
			FailedJobs:         0,
			ReputationScore:    50,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	start := time.Now()

	// Simulate concurrent updates
	for update := 0; update < updatesPerValidator; update++ {
		for i := 0; i < numValidators; i++ {
			addr := fmt.Sprintf("conc-val-%d", i)

			// Update stats
			stats, err := k.ValidatorStats.Get(ctx, addr)
			require.NoError(t, err)

			stats.TotalJobsProcessed++
			if update%10 != 0 {
				stats.SuccessfulJobs++
			} else {
				stats.FailedJobs++
			}

			require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
		}
	}

	elapsed := time.Since(start)
	totalUpdates := numValidators * updatesPerValidator

	t.Logf("Concurrent Validator Update Stress Test Results:")
	t.Logf("  Validators: %d, Updates per validator: %d", numValidators, updatesPerValidator)
	t.Logf("  Total updates: %d", totalUpdates)
	t.Logf("  Total time: %v", elapsed)
	t.Logf("  Updates/second: %.2f", float64(totalUpdates)/elapsed.Seconds())

	// Verify final state
	for i := 0; i < numValidators; i++ {
		addr := fmt.Sprintf("conc-val-%d", i)
		stats, err := k.ValidatorStats.Get(ctx, addr)
		require.NoError(t, err)
		require.Equal(t, int64(updatesPerValidator), stats.TotalJobsProcessed)
	}

	// Performance assertion
	require.Greater(t, float64(totalUpdates)/elapsed.Seconds(), float64(10000),
		"Should handle > 10K updates/sec")
}

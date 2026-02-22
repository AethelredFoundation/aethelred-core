package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEK 31-32: Remediation Sprint 2 — Medium Findings Tests
//
// These tests verify:
//   1. Rate limiter (7 tests)
//   2. Input sanitization (8 tests)
//   3. State consistency checks (4 tests)
//   4. Emergency circuit breaker (7 tests)
//   5. Validator performance scoring (6 tests)
//   6. Week 31-32 remediation registry (2 tests)
//
// Total: 34 tests
// =============================================================================

// =============================================================================
// Section 1: Rate Limiter
// =============================================================================

func TestRateLimiter_New(t *testing.T) {
	rl := keeper.NewJobRateLimiter(keeper.DefaultRateLimitConfig())
	require.NotNil(t, rl)
}

func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	config := keeper.RateLimitConfig{
		MaxJobsPerWindow: 5,
		WindowBlocks:     10,
		GlobalMaxPending: 100,
	}
	rl := keeper.NewJobRateLimiter(config)

	for i := 0; i < 5; i++ {
		require.NoError(t, rl.CheckLimit("addr1", 100))
		rl.RecordSubmission("addr1", 100)
	}
}

func TestRateLimiter_BlocksExcessSubmissions(t *testing.T) {
	config := keeper.RateLimitConfig{
		MaxJobsPerWindow: 3,
		WindowBlocks:     10,
		GlobalMaxPending: 100,
	}
	rl := keeper.NewJobRateLimiter(config)

	for i := 0; i < 3; i++ {
		require.NoError(t, rl.CheckLimit("addr1", 100))
		rl.RecordSubmission("addr1", 100)
	}

	// 4th submission should be blocked
	err := rl.CheckLimit("addr1", 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rate limit exceeded")
}

func TestRateLimiter_WindowExpiration(t *testing.T) {
	config := keeper.RateLimitConfig{
		MaxJobsPerWindow: 2,
		WindowBlocks:     10,
		GlobalMaxPending: 100,
	}
	rl := keeper.NewJobRateLimiter(config)

	// Submit 2 at block 100
	rl.RecordSubmission("addr1", 100)
	rl.RecordSubmission("addr1", 100)

	// At block 100+10=110, old submissions should be expired
	require.NoError(t, rl.CheckLimit("addr1", 111))
}

func TestRateLimiter_PerAddressIsolation(t *testing.T) {
	config := keeper.RateLimitConfig{
		MaxJobsPerWindow: 2,
		WindowBlocks:     10,
		GlobalMaxPending: 100,
	}
	rl := keeper.NewJobRateLimiter(config)

	// addr1 maxes out
	rl.RecordSubmission("addr1", 100)
	rl.RecordSubmission("addr1", 100)
	require.Error(t, rl.CheckLimit("addr1", 100))

	// addr2 is unaffected
	require.NoError(t, rl.CheckLimit("addr2", 100))
}

func TestRateLimiter_SubmissionsInWindow(t *testing.T) {
	config := keeper.RateLimitConfig{
		MaxJobsPerWindow: 10,
		WindowBlocks:     10,
		GlobalMaxPending: 100,
	}
	rl := keeper.NewJobRateLimiter(config)

	rl.RecordSubmission("addr1", 95)
	rl.RecordSubmission("addr1", 98)
	rl.RecordSubmission("addr1", 100)

	// At block 100, window starts at 90 — all 3 are in window
	require.Equal(t, 3, rl.SubmissionsInWindow("addr1", 100))

	// At block 106, window starts at 96 — only 2 are in window
	require.Equal(t, 2, rl.SubmissionsInWindow("addr1", 106))
}

func TestRateLimiter_EmptyAddress(t *testing.T) {
	rl := keeper.NewJobRateLimiter(keeper.DefaultRateLimitConfig())
	err := rl.CheckLimit("", 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

// =============================================================================
// Section 2: Input Sanitization
// =============================================================================

func TestSanitizePurpose_Valid(t *testing.T) {
	result, err := keeper.SanitizePurpose("credit_scoring")
	require.NoError(t, err)
	require.Equal(t, "credit_scoring", result.Sanitized)
	require.Empty(t, result.Warnings)
}

func TestSanitizePurpose_WithSpaces(t *testing.T) {
	result, err := keeper.SanitizePurpose("credit scoring test")
	require.NoError(t, err)
	require.Equal(t, "credit scoring test", result.Sanitized)
}

func TestSanitizePurpose_RemovesSpecialChars(t *testing.T) {
	result, err := keeper.SanitizePurpose("credit<script>alert('xss')</script>scoring")
	require.NoError(t, err)
	require.NotContains(t, result.Sanitized, "<")
	require.NotContains(t, result.Sanitized, ">")
	require.NotEmpty(t, result.Warnings)
}

func TestSanitizePurpose_Empty(t *testing.T) {
	_, err := keeper.SanitizePurpose("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestSanitizePurpose_TooLong(t *testing.T) {
	long := make([]byte, keeper.MaxPurposeLength+1)
	for i := range long {
		long[i] = 'a'
	}
	_, err := keeper.SanitizePurpose(string(long))
	require.Error(t, err)
	require.Contains(t, err.Error(), "maximum length")
}

func TestValidateHexHash_Valid(t *testing.T) {
	hash := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	err := keeper.ValidateHexHash(hash, "model_hash", 32)
	require.NoError(t, err)
}

func TestValidateHexHash_Invalid(t *testing.T) {
	err := keeper.ValidateHexHash("xyz123", "model_hash", 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-hex")
}

func TestValidateHexHash_WrongLength(t *testing.T) {
	err := keeper.ValidateHexHash("aabb", "model_hash", 32)
	require.Error(t, err)
	require.Contains(t, err.Error(), "64 hex characters")
}

// =============================================================================
// Section 3: State Consistency Checks
// =============================================================================

func TestEndBlockConsistencyChecks_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checks := keeper.EndBlockConsistencyChecks(ctx, k)
	require.NotEmpty(t, checks)

	for _, check := range checks {
		require.True(t, check.Passed,
			"check %s should pass in clean state: %s", check.Name, check.Description)
	}
}

func TestEndBlockConsistencyChecks_OrphanDetection(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 3)

	// Create orphan: mark job as completed in Jobs but leave in PendingJobs
	job, err := k.Jobs.Get(ctx, "job-0")
	require.NoError(t, err)
	job.Status = types.JobStatusCompleted
	require.NoError(t, k.Jobs.Set(ctx, "job-0", job))

	checks := keeper.EndBlockConsistencyChecks(ctx, k)

	for _, check := range checks {
		if check.Name == "no_orphan_pending_jobs" {
			require.False(t, check.Passed,
				"orphan check should fail when orphaned pending jobs exist")
			return
		}
	}
	t.Fatal("no_orphan_pending_jobs check not found")
}

func TestEndBlockConsistencyChecks_PerformanceAcceptable(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checks := keeper.EndBlockConsistencyChecks(ctx, k)

	for _, check := range checks {
		require.Less(t, check.Duration.Milliseconds(), int64(100),
			"check %s took too long: %v", check.Name, check.Duration)
	}
}

func TestEndBlockConsistencyChecks_CheckCount(t *testing.T) {
	k, ctx := newTestKeeper(t)
	checks := keeper.EndBlockConsistencyChecks(ctx, k)
	require.GreaterOrEqual(t, len(checks), 3,
		"must run at least 3 consistency checks")
}

// =============================================================================
// Section 4: Emergency Circuit Breaker
// =============================================================================

func TestCircuitBreaker_New(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	require.NotNil(t, cb)
	require.False(t, cb.IsTripped())
}

func TestCircuitBreaker_Trip(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	cb.Trip("critical vulnerability detected", "governance", 1000, 0)

	require.True(t, cb.IsTripped())
	state := cb.State()
	require.Equal(t, "critical vulnerability detected", state.Reason)
	require.Equal(t, "governance", state.TrippedBy)
	require.Equal(t, int64(1000), state.TrippedAt)
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	cb.Trip("test", "gov", 1000, 0)
	require.True(t, cb.IsTripped())

	cb.Reset()
	require.False(t, cb.IsTripped())
}

func TestCircuitBreaker_AutoReset(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	cb.Trip("test", "gov", 1000, 100) // auto-reset after 100 blocks

	// Before auto-reset block
	require.False(t, cb.CheckAutoReset(1050))
	require.True(t, cb.IsTripped())

	// At auto-reset block
	require.True(t, cb.CheckAutoReset(1100))
	require.False(t, cb.IsTripped())
}

func TestCircuitBreaker_NoAutoResetIfZero(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	cb.Trip("test", "gov", 1000, 0) // manual reset only

	require.False(t, cb.CheckAutoReset(999999))
	require.True(t, cb.IsTripped())
}

func TestShouldAcceptJob_Nominal(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	rl := keeper.NewJobRateLimiter(keeper.DefaultRateLimitConfig())

	err := keeper.ShouldAcceptJob(cb, rl, "addr1", 100, 0, keeper.DefaultRateLimitConfig())
	require.NoError(t, err)
}

func TestShouldAcceptJob_CircuitBreakerBlocks(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	cb.Trip("emergency", "gov", 100, 0)

	rl := keeper.NewJobRateLimiter(keeper.DefaultRateLimitConfig())
	err := keeper.ShouldAcceptJob(cb, rl, "addr1", 100, 0, keeper.DefaultRateLimitConfig())
	require.Error(t, err)
	require.Contains(t, err.Error(), "circuit breaker")
}

// =============================================================================
// Section 5: Validator Performance Scoring
// =============================================================================

func TestPerformanceScore_PerfectValidator(t *testing.T) {
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		ReputationScore:   100,
		JobsCompleted:     100,
		JobsFailed:        0,
		AvgResponseBlocks: 1.0,
		ConsecutiveMisses: 0,
		IsOnline:          true,
	})
	require.Equal(t, int64(100), score, "perfect validator should score 100")
}

func TestPerformanceScore_OfflineValidator(t *testing.T) {
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		ReputationScore:   100,
		JobsCompleted:     100,
		IsOnline:          false,
	})
	require.Equal(t, int64(0), score, "offline validator should score 0")
}

func TestPerformanceScore_NewValidator(t *testing.T) {
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		ReputationScore:   50,
		JobsCompleted:     0,
		JobsFailed:        0,
		AvgResponseBlocks: 0,
		ConsecutiveMisses: 0,
		IsOnline:          true,
	})
	// Neutral scores for new validator: reputation=15, completion=15, speed=20, liveness=20 = 70
	require.Greater(t, score, int64(50), "new validator should have reasonable score")
	require.LessOrEqual(t, score, int64(100))
}

func TestPerformanceScore_PoorPerformer(t *testing.T) {
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		ReputationScore:   10,
		JobsCompleted:     10,
		JobsFailed:        90,
		AvgResponseBlocks: 20,
		ConsecutiveMisses: 50,
		IsOnline:          true,
	})
	require.Less(t, score, int64(30), "poor performer should have low score")
}

func TestPerformanceScore_Bounded(t *testing.T) {
	// Test with extreme values to ensure bounds
	score1 := keeper.PerformanceScore(keeper.PerformanceMetrics{
		ReputationScore: 200, // out of normal range
		JobsCompleted:   1000000,
		IsOnline:        true,
	})
	require.LessOrEqual(t, score1, int64(100))
	require.GreaterOrEqual(t, score1, int64(0))

	score2 := keeper.PerformanceScore(keeper.PerformanceMetrics{
		ReputationScore:   -10, // negative
		ConsecutiveMisses: 100,
		IsOnline:          true,
	})
	require.GreaterOrEqual(t, score2, int64(0))
}

func TestPerformanceScore_SpeedTiers(t *testing.T) {
	base := keeper.PerformanceMetrics{
		ReputationScore:   100,
		JobsCompleted:     100,
		ConsecutiveMisses: 0,
		IsOnline:          true,
	}

	fast := base
	fast.AvgResponseBlocks = 1
	scoreFast := keeper.PerformanceScore(fast)

	slow := base
	slow.AvgResponseBlocks = 15
	scoreSlow := keeper.PerformanceScore(slow)

	require.Greater(t, scoreFast, scoreSlow,
		"faster validator should score higher than slower")
}

// =============================================================================
// Section 6: Week 31-32 Remediation Registry
// =============================================================================

func TestWeek31_32Remediations_NonEmpty(t *testing.T) {
	remediations := keeper.Week31_32Remediations()
	require.NotEmpty(t, remediations)
	require.GreaterOrEqual(t, len(remediations), 4,
		"must have at least 4 remediations for Week 31-32")
}

func TestWeek31_32Remediations_AllHaveRequiredFields(t *testing.T) {
	for _, r := range keeper.Week31_32Remediations() {
		require.NotEmpty(t, r.FindingID, "remediation must have finding ID")
		require.NotEmpty(t, r.Description, "remediation %s must have description", r.FindingID)
		require.NotEmpty(t, r.ImplementedIn, "remediation %s must reference implementation file", r.FindingID)
		require.NotEmpty(t, r.TestCoverage, "remediation %s must reference test coverage", r.FindingID)
	}
}

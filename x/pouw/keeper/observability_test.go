package keeper_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// OBSERVABILITY, METRICS & AUDIT TESTS
//
// These tests cover the performance monitoring, rate limiting, circuit
// breaker, audit logging, and health check subsystems added in Week 17-20.
//
// Test sections:
//   1.  Atomic counters & gauges (12 tests)
//   2.  Timing histogram (10 tests)
//   3.  Module metrics snapshot (6 tests)
//   4.  Rate limiter (6 tests)
//   5.  Circuit breaker (10 tests)
//   6.  Audit record creation & hash chaining (12 tests)
//   7.  Audit query/filtering (6 tests)
//   8.  Health checks (5 tests)
//   9.  Benchmark baselines (6 benchmarks)
// =============================================================================

// =============================================================================
// Section 1: Atomic Counters & Gauges
// =============================================================================

func TestMetrics_Counter_Inc(t *testing.T) {
	var c keeper.AtomicCounter
	require.Equal(t, int64(0), c.Get())
	c.Inc()
	require.Equal(t, int64(1), c.Get())
	c.Inc()
	c.Inc()
	require.Equal(t, int64(3), c.Get())
}

func TestMetrics_Counter_Add(t *testing.T) {
	var c keeper.AtomicCounter
	c.Add(100)
	require.Equal(t, int64(100), c.Get())
	c.Add(50)
	require.Equal(t, int64(150), c.Get())
}

func TestMetrics_Counter_Reset(t *testing.T) {
	var c keeper.AtomicCounter
	c.Inc()
	c.Inc()
	c.Inc()
	c.Reset()
	require.Equal(t, int64(0), c.Get())
}

func TestMetrics_Counter_ConcurrentAccess(t *testing.T) {
	var c keeper.AtomicCounter
	const goroutines = 100
	const incrementsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < incrementsPerGoroutine; i++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int64(goroutines*incrementsPerGoroutine), c.Get(),
		"concurrent increments must not lose data")
}

func TestMetrics_Gauge_SetAndGet(t *testing.T) {
	var g keeper.AtomicGauge
	require.Equal(t, int64(0), g.Get())
	g.Set(42)
	require.Equal(t, int64(42), g.Get())
	g.Set(0)
	require.Equal(t, int64(0), g.Get())
}

func TestMetrics_Gauge_IncDec(t *testing.T) {
	var g keeper.AtomicGauge
	g.Inc()
	g.Inc()
	g.Inc()
	require.Equal(t, int64(3), g.Get())
	g.Dec()
	require.Equal(t, int64(2), g.Get())
}

func TestMetrics_Gauge_ConcurrentAccess(t *testing.T) {
	var g keeper.AtomicGauge
	const goroutines = 100
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half increment, half decrement
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				g.Inc()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				g.Dec()
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int64(0), g.Get(),
		"equal increments and decrements should net to zero")
}

func TestMetrics_Counter_ZeroInitialization(t *testing.T) {
	var c keeper.AtomicCounter
	require.Equal(t, int64(0), c.Get(), "zero-value counter should start at 0")
}

func TestMetrics_Gauge_ZeroInitialization(t *testing.T) {
	var g keeper.AtomicGauge
	require.Equal(t, int64(0), g.Get(), "zero-value gauge should start at 0")
}

func TestMetrics_Counter_NegativeAdd(t *testing.T) {
	var c keeper.AtomicCounter
	c.Add(10)
	c.Add(-3)
	require.Equal(t, int64(7), c.Get(), "negative add should reduce counter")
}

func TestMetrics_Gauge_NegativeValues(t *testing.T) {
	var g keeper.AtomicGauge
	g.Set(-100)
	require.Equal(t, int64(-100), g.Get(), "gauge should support negative values")
}

func TestMetrics_Gauge_DecBelowZero(t *testing.T) {
	var g keeper.AtomicGauge
	g.Dec()
	require.Equal(t, int64(-1), g.Get(), "gauge should go below zero")
}

// =============================================================================
// Section 2: Timing Histogram
// =============================================================================

func TestMetrics_Histogram_Empty(t *testing.T) {
	h := keeper.NewTimingHistogram(100)
	summary := h.Summary()
	require.Equal(t, int64(0), summary.Count)
	require.Equal(t, time.Duration(0), summary.Min)
	require.Equal(t, time.Duration(0), summary.Max)
}

func TestMetrics_Histogram_SingleSample(t *testing.T) {
	h := keeper.NewTimingHistogram(100)
	h.Record(5 * time.Millisecond)

	summary := h.Summary()
	require.Equal(t, int64(1), summary.Count)
	require.Equal(t, 5*time.Millisecond, summary.Min)
	require.Equal(t, 5*time.Millisecond, summary.Max)
	require.Equal(t, 5*time.Millisecond, summary.Avg)
}

func TestMetrics_Histogram_MultipleSamples(t *testing.T) {
	h := keeper.NewTimingHistogram(100)
	for i := 1; i <= 10; i++ {
		h.Record(time.Duration(i) * time.Millisecond)
	}

	summary := h.Summary()
	require.Equal(t, int64(10), summary.Count)
	require.Equal(t, 1*time.Millisecond, summary.Min)
	require.Equal(t, 10*time.Millisecond, summary.Max)
	require.Equal(t, 5500*time.Microsecond, summary.Avg) // (1+2+...+10)/10 = 55/10 = 5.5ms
}

func TestMetrics_Histogram_RingBufferOverflow(t *testing.T) {
	h := keeper.NewTimingHistogram(5) // tiny buffer

	for i := 1; i <= 20; i++ {
		h.Record(time.Duration(i) * time.Millisecond)
	}

	summary := h.Summary()
	// Count tracks total, not just buffered
	require.Equal(t, int64(20), summary.Count)
	// Only the last 5 samples (16-20ms) should be in the buffer
	require.Equal(t, 16*time.Millisecond, summary.Min)
	require.Equal(t, 20*time.Millisecond, summary.Max)
}

func TestMetrics_Histogram_P95(t *testing.T) {
	h := keeper.NewTimingHistogram(1000)

	// Record 100 samples: 1ms to 100ms
	for i := 1; i <= 100; i++ {
		h.Record(time.Duration(i) * time.Millisecond)
	}

	summary := h.Summary()
	// P95 should be around 95ms
	require.True(t, summary.P95 >= 90*time.Millisecond,
		"P95 should be >= 90ms, got %v", summary.P95)
	require.True(t, summary.P95 <= 100*time.Millisecond,
		"P95 should be <= 100ms, got %v", summary.P95)
}

func TestMetrics_Histogram_P99(t *testing.T) {
	h := keeper.NewTimingHistogram(1000)

	for i := 1; i <= 100; i++ {
		h.Record(time.Duration(i) * time.Millisecond)
	}

	summary := h.Summary()
	require.True(t, summary.P99 >= 95*time.Millisecond,
		"P99 should be >= 95ms, got %v", summary.P99)
}

func TestMetrics_Histogram_ConcurrentRecord(t *testing.T) {
	h := keeper.NewTimingHistogram(1000)
	const goroutines = 50
	const samples = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < samples; i++ {
				h.Record(time.Duration(offset+i) * time.Microsecond)
			}
		}(g * samples)
	}
	wg.Wait()

	require.Equal(t, int64(goroutines*samples), h.Count(),
		"all samples must be counted")
}

func TestMetrics_Histogram_ZeroCapacity(t *testing.T) {
	// Zero capacity should default to 1000
	h := keeper.NewTimingHistogram(0)
	h.Record(1 * time.Millisecond)
	require.Equal(t, int64(1), h.Count())
}

func TestMetrics_Histogram_AllSameDuration(t *testing.T) {
	h := keeper.NewTimingHistogram(100)
	for i := 0; i < 50; i++ {
		h.Record(10 * time.Millisecond)
	}

	summary := h.Summary()
	require.Equal(t, 10*time.Millisecond, summary.Min)
	require.Equal(t, 10*time.Millisecond, summary.Max)
	require.Equal(t, 10*time.Millisecond, summary.Avg)
	require.Equal(t, 10*time.Millisecond, summary.P50)
	require.Equal(t, 10*time.Millisecond, summary.P95)
}

func TestMetrics_Histogram_SubMicrosecond(t *testing.T) {
	h := keeper.NewTimingHistogram(100)
	h.Record(500 * time.Nanosecond)
	h.Record(100 * time.Nanosecond)

	summary := h.Summary()
	require.Equal(t, 100*time.Nanosecond, summary.Min)
	require.Equal(t, 500*time.Nanosecond, summary.Max)
}

// =============================================================================
// Section 3: Module Metrics Snapshot
// =============================================================================

func TestMetrics_ModuleMetrics_NewIsZero(t *testing.T) {
	m := keeper.NewModuleMetrics()

	require.Equal(t, int64(0), m.JobsSubmitted.Get())
	require.Equal(t, int64(0), m.JobsCompleted.Get())
	require.Equal(t, int64(0), m.ConsensusRounds.Get())
	require.Equal(t, int64(0), m.VerificationsTotal.Get())
	require.Equal(t, int64(0), m.TokensBurned.Get())
}

func TestMetrics_ModuleMetrics_Snapshot(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobsSubmitted.Add(100)
	m.JobsCompleted.Add(95)
	m.JobsFailed.Add(5)
	m.ConsensusRounds.Add(50)
	m.ConsensusReached.Add(48)
	m.TokensBurned.Add(1000000)
	m.ActiveValidators.Set(3)

	now := time.Now().UTC()
	snap := m.Snapshot(200, now)

	require.Equal(t, int64(200), snap.BlockHeight)
	require.Equal(t, int64(100), snap.JobsSubmitted)
	require.Equal(t, int64(95), snap.JobsCompleted)
	require.Equal(t, int64(5), snap.JobsFailed)
	require.Equal(t, int64(50), snap.ConsensusRounds)
	require.Equal(t, int64(48), snap.ConsensusReached)
	require.Equal(t, int64(1000000), snap.TokensBurnedUaeth)
	require.Equal(t, int64(3), snap.ActiveValidators)
}

func TestMetrics_ModuleMetrics_Reset(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobsSubmitted.Add(100)
	m.ConsensusRounds.Add(50)
	m.ActiveValidators.Set(5)
	m.JobCompletionTime.Record(10 * time.Millisecond)

	m.Reset()

	require.Equal(t, int64(0), m.JobsSubmitted.Get())
	require.Equal(t, int64(0), m.ConsensusRounds.Get())
	require.Equal(t, int64(0), m.ActiveValidators.Get())
	require.Equal(t, int64(0), m.JobCompletionTime.Count())
}

func TestMetrics_ModuleMetrics_SnapshotWithTimings(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobCompletionTime.Record(5 * time.Millisecond)
	m.JobCompletionTime.Record(10 * time.Millisecond)
	m.JobCompletionTime.Record(15 * time.Millisecond)

	snap := m.Snapshot(100, time.Now())

	require.NotNil(t, snap.JobCompletionMs)
	require.Equal(t, int64(3), snap.JobCompletionMs.Count)
	require.InDelta(t, 5.0, snap.JobCompletionMs.MinMs, 0.1)
	require.InDelta(t, 15.0, snap.JobCompletionMs.MaxMs, 0.1)
}

func TestMetrics_ModuleMetrics_SnapshotNoTimings(t *testing.T) {
	m := keeper.NewModuleMetrics()
	snap := m.Snapshot(100, time.Now())

	// No timing data recorded, should be nil
	require.Nil(t, snap.JobCompletionMs)
	require.Nil(t, snap.ConsensusRoundMs)
	require.Nil(t, snap.VerificationMs)
}

func TestMetrics_ModuleMetrics_ConcurrentSnapshot(t *testing.T) {
	m := keeper.NewModuleMetrics()
	const goroutines = 20

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half write, half snapshot
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.JobsSubmitted.Inc()
				m.VerificationsTotal.Inc()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = m.Snapshot(int64(j), time.Now())
			}
		}()
	}
	wg.Wait()

	// Verify counts are consistent
	require.Equal(t, int64(goroutines*100), m.JobsSubmitted.Get())
	require.Equal(t, int64(goroutines*100), m.VerificationsTotal.Get())
}

// =============================================================================
// Section 4: Rate Limiter
// =============================================================================

func TestMetrics_RateLimiter_AllowWithinLimit(t *testing.T) {
	rl := keeper.NewRateLimiter(5, time.Second)

	for i := 0; i < 5; i++ {
		require.True(t, rl.Allow(), "request %d should be allowed", i)
	}
}

func TestMetrics_RateLimiter_RejectOverLimit(t *testing.T) {
	rl := keeper.NewRateLimiter(3, time.Hour) // long window so no refill

	require.True(t, rl.Allow())
	require.True(t, rl.Allow())
	require.True(t, rl.Allow())
	require.False(t, rl.Allow(), "4th request should be rejected")
	require.False(t, rl.Allow(), "5th request should be rejected")
}

func TestMetrics_RateLimiter_Remaining(t *testing.T) {
	rl := keeper.NewRateLimiter(10, time.Hour)

	require.Equal(t, int64(10), rl.Remaining())
	rl.Allow()
	require.Equal(t, int64(9), rl.Remaining())
}

func TestMetrics_RateLimiter_AllowN(t *testing.T) {
	rl := keeper.NewRateLimiter(10, time.Hour)

	require.True(t, rl.AllowN(5), "batch of 5 should be allowed")
	require.Equal(t, int64(5), rl.Remaining())
	require.True(t, rl.AllowN(5), "batch of 5 should be allowed (10 total)")
	require.False(t, rl.AllowN(1), "should be exhausted")
}

func TestMetrics_RateLimiter_AllowNRejectIfInsufficient(t *testing.T) {
	rl := keeper.NewRateLimiter(5, time.Hour)

	require.False(t, rl.AllowN(6), "requesting 6 from limit of 5 should fail")
	require.Equal(t, int64(5), rl.Remaining(), "tokens should not be consumed on rejection")
}

func TestMetrics_RateLimiter_ConcurrentAccess(t *testing.T) {
	rl := keeper.NewRateLimiter(1000, time.Hour)
	const goroutines = 50
	const requestsPerGoroutine = 20

	var allowed int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			localAllowed := int64(0)
			for i := 0; i < requestsPerGoroutine; i++ {
				if rl.Allow() {
					localAllowed++
				}
			}
			mu.Lock()
			allowed += localAllowed
			mu.Unlock()
		}()
	}
	wg.Wait()

	require.Equal(t, int64(goroutines*requestsPerGoroutine), allowed,
		"all 1000 requests should be allowed (limit is 1000)")
}

// =============================================================================
// Section 5: Circuit Breaker
// =============================================================================

func TestMetrics_CircuitBreaker_InitClosed(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 3, time.Second)
	require.Equal(t, keeper.CircuitClosed, cb.State())
	require.True(t, cb.Allow())
}

func TestMetrics_CircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 3, time.Hour)

	cb.RecordFailure()
	require.Equal(t, keeper.CircuitClosed, cb.State())
	cb.RecordFailure()
	require.Equal(t, keeper.CircuitClosed, cb.State())
	cb.RecordFailure()
	require.Equal(t, keeper.CircuitOpen, cb.State())
	require.False(t, cb.Allow(), "open circuit should reject requests")
}

func TestMetrics_CircuitBreaker_SuccessResetsCount(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 3, time.Hour)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // reset
	cb.RecordFailure()
	cb.RecordFailure()

	require.Equal(t, keeper.CircuitClosed, cb.State(),
		"success should reset consecutive failure count")
}

func TestMetrics_CircuitBreaker_HalfOpenAfterCooldown(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 1, 10*time.Millisecond)

	cb.RecordFailure()
	require.Equal(t, keeper.CircuitOpen, cb.State())
	require.False(t, cb.Allow())

	// Wait for cooldown
	time.Sleep(20 * time.Millisecond)
	require.True(t, cb.Allow(), "should allow after cooldown (half-open)")
	require.Equal(t, keeper.CircuitHalfOpen, cb.State())
}

func TestMetrics_CircuitBreaker_ClosesOnHalfOpenSuccess(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 1, 10*time.Millisecond)

	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)

	require.True(t, cb.Allow()) // transitions to half-open
	cb.RecordSuccess()          // transitions to closed

	require.Equal(t, keeper.CircuitClosed, cb.State())
	require.True(t, cb.Allow())
}

func TestMetrics_CircuitBreaker_ReopensOnHalfOpenFailure(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 1, 10*time.Millisecond)

	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)

	require.True(t, cb.Allow()) // half-open
	cb.RecordFailure()          // back to open

	require.Equal(t, keeper.CircuitOpen, cb.State())
}

func TestMetrics_CircuitBreaker_TotalTrips(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 1, 10*time.Millisecond)

	require.Equal(t, int64(0), cb.TotalTrips())

	cb.RecordFailure()
	require.Equal(t, int64(1), cb.TotalTrips())

	// Recovery cycle
	time.Sleep(20 * time.Millisecond)
	cb.Allow()
	cb.RecordSuccess()

	// Trip again
	cb.RecordFailure()
	require.Equal(t, int64(2), cb.TotalTrips())
}

func TestMetrics_CircuitBreaker_Name(t *testing.T) {
	cb := keeper.NewCircuitBreaker("verification_engine", 5, time.Second)
	require.Equal(t, "verification_engine", cb.Name())
}

func TestMetrics_CircuitBreaker_StateString(t *testing.T) {
	require.Equal(t, "closed", keeper.CircuitClosed.String())
	require.Equal(t, "open", keeper.CircuitOpen.String())
	require.Equal(t, "half_open", keeper.CircuitHalfOpen.String())
}

func TestMetrics_CircuitBreaker_ConcurrentAccess(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 100, time.Hour)
	const goroutines = 20

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cb.RecordFailure()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = cb.Allow()
				_ = cb.State()
			}
		}()
	}
	wg.Wait()

	// Should not panic; state should be consistent
	state := cb.State()
	require.Contains(t, []keeper.CircuitBreakerState{keeper.CircuitClosed, keeper.CircuitOpen, keeper.CircuitHalfOpen}, state)
}

// =============================================================================
// Section 6: Audit Record Creation & Hash Chaining
// =============================================================================

func TestAudit_NewLogger(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	require.NotNil(t, al)
	require.Equal(t, uint64(0), al.Sequence())
	require.Equal(t, "genesis", al.LastHash())
}

func TestAudit_RecordCreatesEntry(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	record := al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test_action", "test_actor", map[string]string{
		"key": "value",
	})

	require.NotNil(t, record)
	require.Equal(t, uint64(1), record.Sequence)
	require.Equal(t, "genesis", record.PreviousHash)
	require.NotEmpty(t, record.RecordHash)
	require.Equal(t, keeper.AuditCategoryJob, record.Category)
	require.Equal(t, keeper.AuditSeverityInfo, record.Severity)
	require.Equal(t, "test_action", record.Action)
	require.Equal(t, "test_actor", record.Actor)
	require.Equal(t, "value", record.Details["key"])
}

func TestAudit_HashChaining(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	r1 := al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "action1", "actor1", nil)
	r2 := al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "action2", "actor2", nil)
	r3 := al.Record(sdkCtx, keeper.AuditCategoryConsensus, keeper.AuditSeverityWarning, "action3", "actor3", nil)

	// Each record's PreviousHash must equal the preceding record's RecordHash
	require.Equal(t, "genesis", r1.PreviousHash)
	require.Equal(t, r1.RecordHash, r2.PreviousHash)
	require.Equal(t, r2.RecordHash, r3.PreviousHash)
	require.Equal(t, r3.RecordHash, al.LastHash())
}

func TestAudit_VerifyChain_Valid(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	for i := 0; i < 20; i++ {
		al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo,
			fmt.Sprintf("action_%d", i), "actor", map[string]string{
				"iteration": fmt.Sprintf("%d", i),
			})
	}

	err := al.VerifyChain()
	require.NoError(t, err, "hash chain of valid records should verify")
}

func TestAudit_DeterministicHashing(t *testing.T) {
	// Same inputs should produce the same hash
	al1 := keeper.NewAuditLogger(100)
	al2 := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	details := map[string]string{"a": "1", "b": "2"}
	r1 := al1.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "actor", details)
	r2 := al2.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "actor", details)

	require.Equal(t, r1.RecordHash, r2.RecordHash,
		"identical inputs must produce identical hashes")
}

func TestAudit_DifferentInputsDifferentHashes(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	r1 := al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "action_a", "actor", nil)
	r2 := al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "action_b", "actor", nil)

	require.NotEqual(t, r1.RecordHash, r2.RecordHash,
		"different actions should produce different hashes")
}

func TestAudit_SequenceIncrementsCorrectly(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	for i := 1; i <= 10; i++ {
		r := al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "actor", nil)
		require.Equal(t, uint64(i), r.Sequence)
	}
	require.Equal(t, uint64(10), al.Sequence())
}

func TestAudit_TotalEmitted(t *testing.T) {
	al := keeper.NewAuditLogger(5) // small buffer
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	for i := 0; i < 20; i++ {
		al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "actor", nil)
	}

	require.Equal(t, uint64(20), al.TotalEmitted())
	// Buffer only holds 5, but total emitted tracks all
	records := al.GetRecords()
	require.Len(t, records, 5, "buffer should be capped at 5")
}

func TestAudit_ExportJSON(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "actor",
		map[string]string{"key": "value"})

	jsonBytes, err := al.ExportJSON()
	require.NoError(t, err)
	require.Contains(t, string(jsonBytes), "test")
	require.Contains(t, string(jsonBytes), "record_hash")
}

func TestAudit_ConvenienceHelpers(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	al.AuditJobSubmitted(sdkCtx, "job-1", "model-hash", "requester", "tee")
	al.AuditJobCompleted(sdkCtx, "job-1", "seal-1", "output-hash", 3)
	al.AuditJobFailed(sdkCtx, "job-2", "timeout")
	al.AuditConsensusReached(sdkCtx, "job-1", 3, 3)
	al.AuditSlashingApplied(sdkCtx, "validator-1", "invalid_output", "high", "10000uaeth", "job-3")
	al.AuditParamChange(sdkCtx, "gov-authority", []keeper.ParamFieldChange{
		{Field: "min_validators", OldValue: "3", NewValue: "5"},
	})

	require.Equal(t, uint64(6), al.TotalEmitted())

	// Verify chain is still valid after all convenience calls
	err := al.VerifyChain()
	require.NoError(t, err)
}

func TestAudit_SecurityAlertSeverity(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	al.AuditSecurityAlert(sdkCtx, "double_sign", "validator submitted conflicting outputs", map[string]string{
		"validator": "val-1",
		"job_id":    "job-99",
	})

	records := al.GetRecords()
	require.Len(t, records, 1)
	require.Equal(t, keeper.AuditSeverityCritical, records[0].Severity)
	require.Equal(t, keeper.AuditCategorySecurity, records[0].Category)
}

func TestAudit_EvidenceDetectedSeverity(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	// "invalid_output" should be warning
	al.AuditEvidenceDetected(sdkCtx, "val-1", "invalid_output", "consensus", "job-1")
	// "double_sign" should be critical
	al.AuditEvidenceDetected(sdkCtx, "val-2", "double_sign", "consensus", "job-2")
	// "collusion" should be critical
	al.AuditEvidenceDetected(sdkCtx, "val-3", "collusion", "consensus", "job-3")

	records := al.GetRecords()
	require.Equal(t, keeper.AuditSeverityWarning, records[0].Severity)
	require.Equal(t, keeper.AuditSeverityCritical, records[1].Severity)
	require.Equal(t, keeper.AuditSeverityCritical, records[2].Severity)
}

// =============================================================================
// Section 7: Audit Query & Filtering
// =============================================================================

func TestAudit_GetRecordsSince(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	// All records at height 100 (from sdkTestContext)
	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "a", "actor", nil)
	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "b", "actor", nil)

	records := al.GetRecordsSince(100)
	require.Len(t, records, 2)

	records = al.GetRecordsSince(101)
	require.Len(t, records, 0)
}

func TestAudit_GetRecordsByCategory(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "a", "actor", nil)
	al.Record(sdkCtx, keeper.AuditCategoryConsensus, keeper.AuditSeverityInfo, "b", "actor", nil)
	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "c", "actor", nil)
	al.Record(sdkCtx, keeper.AuditCategorySlashing, keeper.AuditSeverityCritical, "d", "actor", nil)

	jobRecords := al.GetRecordsByCategory(keeper.AuditCategoryJob)
	require.Len(t, jobRecords, 2)

	consensusRecords := al.GetRecordsByCategory(keeper.AuditCategoryConsensus)
	require.Len(t, consensusRecords, 1)

	slashRecords := al.GetRecordsByCategory(keeper.AuditCategorySlashing)
	require.Len(t, slashRecords, 1)
}

func TestAudit_GetRecordsBySeverity(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "a", "actor", nil)
	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityWarning, "b", "actor", nil)
	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityCritical, "c", "actor", nil)
	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "d", "actor", nil)

	infoAndAbove := al.GetRecordsBySeverity(keeper.AuditSeverityInfo)
	require.Len(t, infoAndAbove, 4)

	warningAndAbove := al.GetRecordsBySeverity(keeper.AuditSeverityWarning)
	require.Len(t, warningAndAbove, 2)

	criticalOnly := al.GetRecordsBySeverity(keeper.AuditSeverityCritical)
	require.Len(t, criticalOnly, 1)
}

func TestAudit_GetRecords_ReturnsDefensiveCopy(t *testing.T) {
	al := keeper.NewAuditLogger(100)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "actor", nil)

	records1 := al.GetRecords()
	records2 := al.GetRecords()

	// Modifying one copy should not affect the other
	records1[0].Action = "modified"
	require.NotEqual(t, records1[0].Action, records2[0].Action)
}

func TestAudit_EmptyQueryResults(t *testing.T) {
	al := keeper.NewAuditLogger(100)

	require.Len(t, al.GetRecords(), 0)
	require.Len(t, al.GetRecordsSince(0), 0)
	require.Len(t, al.GetRecordsByCategory(keeper.AuditCategoryJob), 0)
	require.Len(t, al.GetRecordsBySeverity(keeper.AuditSeverityInfo), 0)
}

func TestAudit_ConcurrentAccess(t *testing.T) {
	al := keeper.NewAuditLogger(1000)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)
	const goroutines = 20
	const recordsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half write, half read
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < recordsPerGoroutine; j++ {
				al.Record(sdkCtx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo,
					fmt.Sprintf("action_%d_%d", id, j), "actor", nil)
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < recordsPerGoroutine; j++ {
				_ = al.GetRecords()
				_ = al.GetRecordsBySeverity(keeper.AuditSeverityInfo)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, uint64(goroutines*recordsPerGoroutine), al.TotalEmitted())
}

// =============================================================================
// Section 8: Health Checks
// =============================================================================

func TestHealth_AllHealthyWhenFresh(t *testing.T) {
	m := keeper.NewModuleMetrics()
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	health := m.CheckHealth(sdkCtx)
	require.True(t, health.Healthy, "fresh metrics should be healthy")
	require.Greater(t, len(health.Checks), 0)
}

func TestHealth_UnhealthyPendingJobs(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobsPending.Set(5000)
	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	health := m.CheckHealth(sdkCtx)
	require.False(t, health.Healthy, "5000 pending jobs should be unhealthy")

	// Find the pending_jobs check
	found := false
	for _, check := range health.Checks {
		if check.Name == "pending_jobs" {
			require.False(t, check.Healthy)
			found = true
		}
	}
	require.True(t, found, "should have a pending_jobs health check")
}

func TestHealth_UnhealthyConsensusRate(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.ConsensusRounds.Add(100)
	m.ConsensusReached.Add(20) // 20% success rate

	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	health := m.CheckHealth(sdkCtx)
	require.False(t, health.Healthy, "20%% consensus rate should be unhealthy")
}

func TestHealth_HealthyConsensusRate(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.ConsensusRounds.Add(100)
	m.ConsensusReached.Add(95) // 95% success rate

	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	health := m.CheckHealth(sdkCtx)

	// Check that consensus_rate is healthy
	for _, check := range health.Checks {
		if check.Name == "consensus_rate" {
			require.True(t, check.Healthy, "95%% consensus rate should be healthy")
		}
	}
}

func TestHealth_UnhealthySlashingRate(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobsCompleted.Add(100)
	m.SlashingPenaltiesApplied.Add(30) // 30% slashing rate

	ctx := sdkTestContext()
	sdkCtx := unwrapSDKContext(ctx)

	health := m.CheckHealth(sdkCtx)
	require.False(t, health.Healthy, "30%% slashing rate should be unhealthy")
}

// =============================================================================
// Section 9: Benchmark Baselines
// =============================================================================

func BenchmarkMetrics_CounterInc(b *testing.B) {
	var c keeper.AtomicCounter
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Inc()
	}
}

func BenchmarkMetrics_GaugeSet(b *testing.B) {
	var g keeper.AtomicGauge
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Set(int64(i))
	}
}

func BenchmarkMetrics_HistogramRecord(b *testing.B) {
	h := keeper.NewTimingHistogram(1000)
	d := 5 * time.Millisecond
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Record(d)
	}
}

func BenchmarkMetrics_HistogramSummary(b *testing.B) {
	h := keeper.NewTimingHistogram(1000)
	for i := 0; i < 1000; i++ {
		h.Record(time.Duration(i) * time.Microsecond)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Summary()
	}
}

func BenchmarkFeeBreakdown(b *testing.B) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaeth", 1000000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = keeper.CalculateFeeBreakdown(fee, config, 5)
	}
}

func BenchmarkValidateParams(b *testing.B) {
	params := types.DefaultParams()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = keeper.ValidateParams(params)
	}
}

// =============================================================================
// Test helpers
// =============================================================================

// unwrapSDKContext converts a context.Context from sdkTestContext() into an
// sdk.Context for use with audit and metrics methods that need SDK context.
func unwrapSDKContext(ctx interface{ Value(key interface{}) interface{} }) sdk.Context {
	return sdk.UnwrapSDKContext(ctx.(context.Context))
}

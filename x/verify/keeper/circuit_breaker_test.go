package keeper

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
)

// =============================================================================
// CIRCUIT BREAKER FAILURE SCENARIO TESTS
//
// These tests address the consultant finding regarding missing circuit breaker
// failure scenario test coverage.
// =============================================================================

// TestCircuitBreakerOpensOnFailures verifies that the circuit breaker opens
// after consecutive failures, preventing further requests.
func TestCircuitBreakerOpensOnFailures(t *testing.T) {
	t.Parallel()

	// Create circuit breaker with low threshold for testing
	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 3,
		OpenTimeout:      500 * time.Millisecond,
	})

	// Make requests until circuit opens
	for i := 0; i < 5; i++ {
		if !cb.Allow() {
			t.Logf("Circuit opened after %d failures", i)
			break
		}
		cb.RecordFailure()
	}

	// Circuit should be open now
	assert.False(t, cb.Allow(), "Circuit should be open after failures")
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())
}

// TestCircuitBreakerRecovery verifies that the circuit breaker recovers
// after the timeout period when the service is healthy again.
func TestCircuitBreakerRecovery(t *testing.T) {
	t.Parallel()

	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 2,
		OpenTimeout:      100 * time.Millisecond,
	})

	// Trigger circuit open
	for i := 0; i < 3; i++ {
		if cb.Allow() {
			cb.RecordFailure()
		}
	}
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Wait for half-open
	time.Sleep(150 * time.Millisecond)

	// Circuit should allow request now (half-open or transitioned)
	allowed := cb.Allow()
	assert.True(t, allowed, "Circuit should allow trial request after cooldown")

	if allowed {
		cb.RecordSuccess()
	}

	// After success, circuit should be closed
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
}

// TestCircuitBreakerPreventsOverload verifies that the circuit breaker
// prevents overload during failure scenarios.
func TestCircuitBreakerPreventsOverload(t *testing.T) {
	t.Parallel()

	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 3,
		OpenTimeout:      200 * time.Millisecond,
	})

	// Simulate concurrent requests
	var wg sync.WaitGroup
	blocked := int32(0)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !cb.Allow() {
				atomic.AddInt32(&blocked, 1)
				return
			}
			// Simulate request
			time.Sleep(5 * time.Millisecond)
			cb.RecordFailure()
		}()
		time.Sleep(1 * time.Millisecond)
	}

	wg.Wait()

	// Most requests should have been blocked
	t.Logf("Blocked requests: %d", atomic.LoadInt32(&blocked))
	assert.Greater(t, int(atomic.LoadInt32(&blocked)), 50, "Circuit breaker should block most requests during failure")
}

// TestCircuitBreakerMetrics verifies that circuit breaker metrics are recorded.
func TestCircuitBreakerMetrics(t *testing.T) {
	t.Parallel()

	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 2,
		OpenTimeout:      100 * time.Millisecond,
	})

	// Record some operations
	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	metrics := cb.Metrics()

	// After 2 failures (threshold), circuit opens
	assert.Equal(t, circuitbreaker.StateOpen, metrics.State)
	assert.GreaterOrEqual(t, metrics.OpenCount, int64(1), "Circuit should have opened at least once")
}

// TestCircuitBreakerStateTransitions verifies all state transitions.
func TestCircuitBreakerStateTransitions(t *testing.T) {
	t.Parallel()

	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 2,
		OpenTimeout:      100 * time.Millisecond,
	})

	// Start: Closed
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())

	// Failure 1: Still Closed
	cb.RecordFailure()
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())

	// Failure 2: Opens (threshold reached)
	cb.RecordFailure()
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Cannot make requests while open
	assert.False(t, cb.Allow())

	// Wait for cooldown
	time.Sleep(150 * time.Millisecond)

	// Should allow a test request (half-open)
	assert.True(t, cb.Allow(), "Should allow test request after cooldown")

	// Success should close the circuit
	cb.RecordSuccess()
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
}

// TestCircuitBreakerConcurrentAccess verifies thread safety.
func TestCircuitBreakerConcurrentAccess(t *testing.T) {
	t.Parallel()

	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 100, // High threshold to avoid opening during test
		OpenTimeout:      time.Second,
	})

	var wg sync.WaitGroup
	iterations := 1000
	goroutines := 10

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				cb.Allow()
				if i%2 == 0 {
					cb.RecordSuccess()
				} else {
					cb.RecordFailure()
				}
			}
		}()
	}

	wg.Wait()

	// Should not panic and should have recorded operations
	metrics := cb.Metrics()
	t.Logf("Final state: %s, failures: %d", metrics.State, metrics.FailureCount)
}

// TestCircuitBreakerResetOnSuccess verifies that success resets failure count.
func TestCircuitBreakerResetOnSuccess(t *testing.T) {
	t.Parallel()

	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 3,
		OpenTimeout:      time.Second,
	})

	// Record 2 failures (below threshold)
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())

	// Success should reset the counter
	cb.RecordSuccess()

	// Now we need 3 more failures to open
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())

	// Third failure opens
	cb.RecordFailure()
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())
}

// TestCircuitBreakerReset verifies manual reset functionality.
func TestCircuitBreakerReset(t *testing.T) {
	t.Parallel()

	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 2,
		OpenTimeout:      time.Hour, // Long timeout
	})

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Manual reset
	cb.Reset()
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
	assert.True(t, cb.Allow(), "Should allow requests after reset")
}

// =============================================================================
// BENCHMARK TESTS
// =============================================================================

// BenchmarkCircuitBreakerAllow benchmarks the Allow() check.
func BenchmarkCircuitBreakerAllow(b *testing.B) {
	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 100,
		OpenTimeout:      time.Second,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Allow()
	}
}

// BenchmarkCircuitBreakerConcurrent benchmarks concurrent access.
func BenchmarkCircuitBreakerConcurrent(b *testing.B) {
	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 1000,
		OpenTimeout:      time.Second,
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if cb.Allow() {
				if time.Now().UnixNano()%2 == 0 {
					cb.RecordSuccess()
				} else {
					cb.RecordFailure()
				}
			}
		}
	})
}

// BenchmarkCircuitBreakerSnapshot benchmarks metrics collection.
func BenchmarkCircuitBreakerSnapshot(b *testing.B) {
	cb := circuitbreaker.NewWithConfig(circuitbreaker.Config{
		FailureThreshold: 100,
		OpenTimeout:      time.Second,
	})

	// Pre-populate some state
	for i := 0; i < 50; i++ {
		cb.RecordSuccess()
		cb.RecordFailure()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.Snapshot()
	}
}

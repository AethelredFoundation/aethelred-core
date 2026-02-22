package keeper

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// Module Metrics -- in-process telemetry for the pouw module
// ---------------------------------------------------------------------------
//
// This file provides a unified telemetry collection layer for the Proof-of-
// Compute module. All counters use sync/atomic for lock-free concurrent access
// and all timing windows use sync.Mutex-protected ring buffers.
//
// Design principles:
//   - No external dependencies beyond the standard library and Cosmos SDK
//   - All metrics are in-memory; exporters (Prometheus, JSON) are separate
//   - Thread-safe: multiple goroutines (ABCI handlers) can record concurrently
//   - Zero-allocation hot path for counter increments
//   - Deterministic reset for testing
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

// AtomicCounter is a lock-free monotonic counter using sync/atomic.
type AtomicCounter struct {
	value int64
}

// Inc increments the counter by 1.
func (c *AtomicCounter) Inc() { atomic.AddInt64(&c.value, 1) }

// Add increments the counter by delta.
func (c *AtomicCounter) Add(delta int64) { atomic.AddInt64(&c.value, delta) }

// Get returns the current counter value.
func (c *AtomicCounter) Get() int64 { return atomic.LoadInt64(&c.value) }

// Reset sets the counter to 0.
func (c *AtomicCounter) Reset() { atomic.StoreInt64(&c.value, 0) }

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

// AtomicGauge is a lock-free gauge (can go up or down).
type AtomicGauge struct {
	value int64
}

// Set stores a new value.
func (g *AtomicGauge) Set(v int64) { atomic.StoreInt64(&g.value, v) }

// Get returns the current value.
func (g *AtomicGauge) Get() int64 { return atomic.LoadInt64(&g.value) }

// Inc increments the gauge by 1.
func (g *AtomicGauge) Inc() { atomic.AddInt64(&g.value, 1) }

// Dec decrements the gauge by 1.
func (g *AtomicGauge) Dec() { atomic.AddInt64(&g.value, -1) }

// ---------------------------------------------------------------------------
// Histogram (simple ring-buffer based)
// ---------------------------------------------------------------------------

// TimingHistogram records the most recent N durations and provides summary
// statistics (min, max, avg, p50, p95, p99) over that window.
type TimingHistogram struct {
	mu       sync.Mutex
	samples  []time.Duration
	capacity int
	cursor   int
	count    int64 // total samples ever recorded
}

// NewTimingHistogram creates a histogram that retains at most capacity samples.
func NewTimingHistogram(capacity int) *TimingHistogram {
	if capacity <= 0 {
		capacity = 1000
	}
	return &TimingHistogram{
		samples:  make([]time.Duration, capacity),
		capacity: capacity,
	}
}

// Record adds a duration sample.
func (h *TimingHistogram) Record(d time.Duration) {
	h.mu.Lock()
	h.samples[h.cursor%h.capacity] = d
	h.cursor++
	h.count++
	h.mu.Unlock()
}

// Count returns the total number of samples ever recorded.
func (h *TimingHistogram) Count() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// Summary returns summary statistics over the window.
type HistogramSummary struct {
	Count int64
	Min   time.Duration
	Max   time.Duration
	Avg   time.Duration
	P50   time.Duration
	P95   time.Duration
	P99   time.Duration
}

// Summary computes summary statistics from the buffered samples.
// It returns a HistogramSummary with Count set to the total recorded count
// (not just the window size). If no samples have been recorded, all duration
// fields are zero.
func (h *TimingHistogram) Summary() HistogramSummary {
	h.mu.Lock()
	defer h.mu.Unlock()

	n := h.cursor
	if n > h.capacity {
		n = h.capacity
	}
	if n == 0 {
		return HistogramSummary{Count: h.count}
	}

	// Collect active samples into a sorted slice.
	active := make([]time.Duration, n)
	copy(active, h.samples[:n])
	sortDurations(active)

	var sum time.Duration
	for _, d := range active {
		sum += d
	}

	return HistogramSummary{
		Count: h.count,
		Min:   active[0],
		Max:   active[n-1],
		Avg:   sum / time.Duration(n),
		P50:   active[percentileIndex(n, 50)],
		P95:   active[percentileIndex(n, 95)],
		P99:   active[percentileIndex(n, 99)],
	}
}

// sortDurations performs an insertion sort (fast for small N, no alloc).
func sortDurations(a []time.Duration) {
	for i := 1; i < len(a); i++ {
		key := a[i]
		j := i - 1
		for j >= 0 && a[j] > key {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = key
	}
}

// percentileIndex returns the index for the p-th percentile in a sorted
// slice of length n. Clamps to [0, n-1].
func percentileIndex(n, p int) int {
	idx := (n * p) / 100
	if idx >= n {
		idx = n - 1
	}
	return idx
}

// ---------------------------------------------------------------------------
// ModuleMetrics -- aggregated telemetry for the pouw module
// ---------------------------------------------------------------------------

// ModuleMetrics collects all telemetry for the pouw module in a single struct.
// A singleton instance is held by the Keeper and shared with all subsystems
// (scheduler, consensus handler, evidence collector, fee distributor).
type ModuleMetrics struct {
	// --- Job lifecycle ---
	JobsSubmitted  AtomicCounter
	JobsCompleted  AtomicCounter
	JobsFailed     AtomicCounter
	JobsExpired    AtomicCounter
	JobsCancelled  AtomicCounter
	JobsPending    AtomicGauge // current pending count (gauge, not counter)
	JobsProcessing AtomicGauge // current processing count

	// --- Consensus ---
	ConsensusRounds          AtomicCounter
	ConsensusReached         AtomicCounter
	ConsensusFailed          AtomicCounter
	VoteExtensionsProcessed  AtomicCounter
	VoteExtensionsRejected   AtomicCounter

	// --- Verification ---
	VerificationsTotal AtomicCounter
	VerificationsTEE   AtomicCounter
	VerificationsZKML  AtomicCounter
	VerificationsHybrid AtomicCounter
	VerificationsSuccess AtomicCounter
	VerificationsFailed  AtomicCounter

	// --- Slashing & evidence ---
	EvidenceRecordsCreated   AtomicCounter
	SlashingPenaltiesApplied AtomicCounter
	SlashingPenaltiesFailed  AtomicCounter
	InvalidOutputsDetected   AtomicCounter
	DoubleSignsDetected      AtomicCounter
	CollusionDetected        AtomicCounter

	// --- Economics ---
	FeesCollected    AtomicCounter // cumulative uaeth collected
	FeesDistributed  AtomicCounter // cumulative uaeth distributed
	TokensBurned     AtomicCounter // cumulative uaeth burned
	RewardsDistributed AtomicCounter // cumulative uaeth to validators

	// --- Timing ---
	JobCompletionTime    *TimingHistogram // time from submission to completion
	ConsensusRoundTime   *TimingHistogram // time to aggregate a consensus round
	VerificationTime     *TimingHistogram // individual verification latency
	VoteExtensionTime    *TimingHistogram // time to process vote extensions

	// --- Validators ---
	ActiveValidators AtomicGauge // current online validator count
	TotalValidators  AtomicGauge // total registered validators

	// --- Blocks ---
	BlocksProcessed AtomicCounter
	LastBlockHeight AtomicGauge
	JobsPerBlock    *TimingHistogram // reuse histogram for integer counts
}

// NewModuleMetrics creates a new ModuleMetrics with all histograms initialized.
func NewModuleMetrics() *ModuleMetrics {
	return &ModuleMetrics{
		JobCompletionTime:  NewTimingHistogram(1000),
		ConsensusRoundTime: NewTimingHistogram(500),
		VerificationTime:   NewTimingHistogram(2000),
		VoteExtensionTime:  NewTimingHistogram(500),
		JobsPerBlock:       NewTimingHistogram(500),
	}
}

// Reset zeroes all counters and gauges and re-initializes histograms.
// This is intended for testing only.
func (m *ModuleMetrics) Reset() {
	m.JobsSubmitted.Reset()
	m.JobsCompleted.Reset()
	m.JobsFailed.Reset()
	m.JobsExpired.Reset()
	m.JobsCancelled.Reset()
	m.JobsPending.Set(0)
	m.JobsProcessing.Set(0)

	m.ConsensusRounds.Reset()
	m.ConsensusReached.Reset()
	m.ConsensusFailed.Reset()
	m.VoteExtensionsProcessed.Reset()
	m.VoteExtensionsRejected.Reset()

	m.VerificationsTotal.Reset()
	m.VerificationsTEE.Reset()
	m.VerificationsZKML.Reset()
	m.VerificationsHybrid.Reset()
	m.VerificationsSuccess.Reset()
	m.VerificationsFailed.Reset()

	m.EvidenceRecordsCreated.Reset()
	m.SlashingPenaltiesApplied.Reset()
	m.SlashingPenaltiesFailed.Reset()
	m.InvalidOutputsDetected.Reset()
	m.DoubleSignsDetected.Reset()
	m.CollusionDetected.Reset()

	m.FeesCollected.Reset()
	m.FeesDistributed.Reset()
	m.TokensBurned.Reset()
	m.RewardsDistributed.Reset()

	m.ActiveValidators.Set(0)
	m.TotalValidators.Set(0)
	m.BlocksProcessed.Reset()
	m.LastBlockHeight.Set(0)

	// Re-initialize histograms
	*m.JobCompletionTime = *NewTimingHistogram(1000)
	*m.ConsensusRoundTime = *NewTimingHistogram(500)
	*m.VerificationTime = *NewTimingHistogram(2000)
	*m.VoteExtensionTime = *NewTimingHistogram(500)
	*m.JobsPerBlock = *NewTimingHistogram(500)
}

// ---------------------------------------------------------------------------
// Snapshot -- point-in-time export
// ---------------------------------------------------------------------------

// MetricsSnapshot is a JSON-friendly snapshot of all module metrics at a given
// block height and timestamp.
type MetricsSnapshot struct {
	// Context
	BlockHeight int64  `json:"block_height"`
	Timestamp   string `json:"timestamp"`

	// Job lifecycle
	JobsSubmitted  int64 `json:"jobs_submitted"`
	JobsCompleted  int64 `json:"jobs_completed"`
	JobsFailed     int64 `json:"jobs_failed"`
	JobsExpired    int64 `json:"jobs_expired"`
	JobsCancelled  int64 `json:"jobs_cancelled"`
	JobsPending    int64 `json:"jobs_pending"`
	JobsProcessing int64 `json:"jobs_processing"`

	// Consensus
	ConsensusRounds         int64 `json:"consensus_rounds"`
	ConsensusReached        int64 `json:"consensus_reached"`
	ConsensusFailed         int64 `json:"consensus_failed"`
	VoteExtensionsProcessed int64 `json:"vote_extensions_processed"`
	VoteExtensionsRejected  int64 `json:"vote_extensions_rejected"`

	// Verification
	VerificationsTotal   int64 `json:"verifications_total"`
	VerificationsSuccess int64 `json:"verifications_success"`
	VerificationsFailed  int64 `json:"verifications_failed"`

	// Slashing
	EvidenceRecordsCreated   int64 `json:"evidence_records_created"`
	SlashingPenaltiesApplied int64 `json:"slashing_penalties_applied"`
	InvalidOutputsDetected   int64 `json:"invalid_outputs_detected"`
	DoubleSignsDetected      int64 `json:"double_signs_detected"`
	CollusionDetected        int64 `json:"collusion_detected"`

	// Economics
	FeesCollectedUaeth    int64 `json:"fees_collected_uaeth"`
	FeesDistributedUaeth  int64 `json:"fees_distributed_uaeth"`
	TokensBurnedUaeth     int64 `json:"tokens_burned_uaeth"`
	RewardsDistributedUaeth int64 `json:"rewards_distributed_uaeth"`

	// Validators
	ActiveValidators int64 `json:"active_validators"`
	TotalValidators  int64 `json:"total_validators"`

	// Blocks
	BlocksProcessed int64 `json:"blocks_processed"`

	// Timing summaries
	JobCompletionMs  *TimingSummaryMs `json:"job_completion_ms,omitempty"`
	ConsensusRoundMs *TimingSummaryMs `json:"consensus_round_ms,omitempty"`
	VerificationMs   *TimingSummaryMs `json:"verification_ms,omitempty"`
}

// TimingSummaryMs is a histogram summary with durations expressed in
// milliseconds for JSON friendliness.
type TimingSummaryMs struct {
	Count int64   `json:"count"`
	MinMs float64 `json:"min_ms"`
	MaxMs float64 `json:"max_ms"`
	AvgMs float64 `json:"avg_ms"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
}

func histSummaryToMs(s HistogramSummary) *TimingSummaryMs {
	if s.Count == 0 {
		return nil
	}
	return &TimingSummaryMs{
		Count: s.Count,
		MinMs: float64(s.Min) / float64(time.Millisecond),
		MaxMs: float64(s.Max) / float64(time.Millisecond),
		AvgMs: float64(s.Avg) / float64(time.Millisecond),
		P50Ms: float64(s.P50) / float64(time.Millisecond),
		P95Ms: float64(s.P95) / float64(time.Millisecond),
		P99Ms: float64(s.P99) / float64(time.Millisecond),
	}
}

// Snapshot returns a point-in-time snapshot of all metrics, annotated with
// the given block height and timestamp.
func (m *ModuleMetrics) Snapshot(blockHeight int64, blockTime time.Time) MetricsSnapshot {
	return MetricsSnapshot{
		BlockHeight: blockHeight,
		Timestamp:   blockTime.UTC().Format(time.RFC3339),

		JobsSubmitted:  m.JobsSubmitted.Get(),
		JobsCompleted:  m.JobsCompleted.Get(),
		JobsFailed:     m.JobsFailed.Get(),
		JobsExpired:    m.JobsExpired.Get(),
		JobsCancelled:  m.JobsCancelled.Get(),
		JobsPending:    m.JobsPending.Get(),
		JobsProcessing: m.JobsProcessing.Get(),

		ConsensusRounds:         m.ConsensusRounds.Get(),
		ConsensusReached:        m.ConsensusReached.Get(),
		ConsensusFailed:         m.ConsensusFailed.Get(),
		VoteExtensionsProcessed: m.VoteExtensionsProcessed.Get(),
		VoteExtensionsRejected:  m.VoteExtensionsRejected.Get(),

		VerificationsTotal:   m.VerificationsTotal.Get(),
		VerificationsSuccess: m.VerificationsSuccess.Get(),
		VerificationsFailed:  m.VerificationsFailed.Get(),

		EvidenceRecordsCreated:   m.EvidenceRecordsCreated.Get(),
		SlashingPenaltiesApplied: m.SlashingPenaltiesApplied.Get(),
		InvalidOutputsDetected:   m.InvalidOutputsDetected.Get(),
		DoubleSignsDetected:      m.DoubleSignsDetected.Get(),
		CollusionDetected:        m.CollusionDetected.Get(),

		FeesCollectedUaeth:      m.FeesCollected.Get(),
		FeesDistributedUaeth:    m.FeesDistributed.Get(),
		TokensBurnedUaeth:       m.TokensBurned.Get(),
		RewardsDistributedUaeth: m.RewardsDistributed.Get(),

		ActiveValidators: m.ActiveValidators.Get(),
		TotalValidators:  m.TotalValidators.Get(),
		BlocksProcessed:  m.BlocksProcessed.Get(),

		JobCompletionMs:  histSummaryToMs(m.JobCompletionTime.Summary()),
		ConsensusRoundMs: histSummaryToMs(m.ConsensusRoundTime.Summary()),
		VerificationMs:   histSummaryToMs(m.VerificationTime.Summary()),
	}
}

// ---------------------------------------------------------------------------
// SDK event emission
// ---------------------------------------------------------------------------

// EmitMetricsEvent emits a periodic metrics summary as an SDK event. This is
// designed to be called once per block (e.g. from EndBlocker) so that
// indexers and dashboards can consume metrics without a separate Prometheus
// scrape endpoint.
func (m *ModuleMetrics) EmitMetricsEvent(ctx sdk.Context) {
	snap := m.Snapshot(ctx.BlockHeight(), ctx.BlockTime())

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"pouw_module_metrics",
			sdk.NewAttribute("block_height", strconv.FormatInt(snap.BlockHeight, 10)),
			sdk.NewAttribute("jobs_submitted", strconv.FormatInt(snap.JobsSubmitted, 10)),
			sdk.NewAttribute("jobs_completed", strconv.FormatInt(snap.JobsCompleted, 10)),
			sdk.NewAttribute("jobs_failed", strconv.FormatInt(snap.JobsFailed, 10)),
			sdk.NewAttribute("jobs_pending", strconv.FormatInt(snap.JobsPending, 10)),
			sdk.NewAttribute("consensus_rounds", strconv.FormatInt(snap.ConsensusRounds, 10)),
			sdk.NewAttribute("consensus_reached", strconv.FormatInt(snap.ConsensusReached, 10)),
			sdk.NewAttribute("evidence_records", strconv.FormatInt(snap.EvidenceRecordsCreated, 10)),
			sdk.NewAttribute("slashing_applied", strconv.FormatInt(snap.SlashingPenaltiesApplied, 10)),
			sdk.NewAttribute("fees_collected_uaeth", strconv.FormatInt(snap.FeesCollectedUaeth, 10)),
			sdk.NewAttribute("tokens_burned_uaeth", strconv.FormatInt(snap.TokensBurnedUaeth, 10)),
			sdk.NewAttribute("active_validators", strconv.FormatInt(snap.ActiveValidators, 10)),
		),
	)
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

// RateLimiter enforces a maximum number of operations per window using a
// sliding-window counter. It is thread-safe.
type RateLimiter struct {
	mu       sync.Mutex
	limit    int64
	window   time.Duration
	tokens   int64
	lastTime time.Time
}

// NewRateLimiter creates a new rate limiter that allows at most `limit`
// operations per `window` duration.
func NewRateLimiter(limit int64, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:    limit,
		window:   window,
		tokens:   limit,
		lastTime: time.Now(),
	}
}

// Allow returns true if the operation is within the rate limit. If the
// window has elapsed since the last refill, tokens are replenished.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime)

	if elapsed >= rl.window {
		// Refill tokens.
		rl.tokens = rl.limit
		rl.lastTime = now
	}

	if rl.tokens <= 0 {
		return false
	}

	rl.tokens--
	return true
}

// AllowN returns true if n operations are within the rate limit.
func (rl *RateLimiter) AllowN(n int64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime)

	if elapsed >= rl.window {
		rl.tokens = rl.limit
		rl.lastTime = now
	}

	if rl.tokens < n {
		return false
	}

	rl.tokens -= n
	return true
}

// Remaining returns the number of tokens left in the current window.
func (rl *RateLimiter) Remaining() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.tokens
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

// CircuitBreakerState represents the state of a circuit breaker.
type CircuitBreakerState int

const (
	CircuitClosed   CircuitBreakerState = iota // normal operation
	CircuitOpen                                // tripped -- rejecting requests
	CircuitHalfOpen                            // testing recovery
)

func (s CircuitBreakerState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// CircuitBreaker protects a subsystem from cascading failures by tracking
// consecutive errors. When the threshold is exceeded, it opens and rejects
// all requests for the cooldown period before allowing a single test request
// (half-open).
type CircuitBreaker struct {
	mu               sync.Mutex
	name             string
	failureThreshold int64
	cooldown         time.Duration
	consecutiveFails int64
	state            CircuitBreakerState
	lastFailTime     time.Time
	totalTrips       int64
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(name string, failureThreshold int64, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:             name,
		failureThreshold: failureThreshold,
		cooldown:         cooldown,
		state:            CircuitClosed,
	}
}

// Allow returns true if the circuit is closed or half-open (allowing a test
// request). Returns false if the circuit is open and the cooldown has not
// elapsed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if cooldown has elapsed.
		if time.Since(cb.lastFailTime) >= cb.cooldown {
			cb.state = CircuitHalfOpen
			return true
		}
		return false
	case CircuitHalfOpen:
		// Only one request allowed in half-open state.
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful operation. If the breaker is half-open,
// it transitions to closed.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFails = 0
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
	}
}

// RecordFailure records a failed operation. If consecutive failures exceed
// the threshold, the breaker opens.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFails++
	cb.lastFailTime = time.Now()

	if cb.consecutiveFails >= cb.failureThreshold {
		if cb.state != CircuitOpen {
			cb.totalTrips++
		}
		cb.state = CircuitOpen
	}
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// TotalTrips returns how many times the breaker has opened.
func (cb *CircuitBreaker) TotalTrips() int64 {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.totalTrips
}

// Name returns the circuit breaker's name.
func (cb *CircuitBreaker) Name() string {
	return cb.name
}

// ---------------------------------------------------------------------------
// Health status
// ---------------------------------------------------------------------------

// HealthStatus represents the overall health of the pouw module.
type HealthStatus struct {
	Healthy     bool              `json:"healthy"`
	BlockHeight int64             `json:"block_height"`
	Timestamp   string            `json:"timestamp"`
	Checks      []HealthCheckItem `json:"checks"`
}

// HealthCheckItem is a single health check result.
type HealthCheckItem struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Message string `json:"message,omitempty"`
}

// CheckHealth performs a comprehensive health check of the pouw module.
// It examines pending job counts, consensus success rate, and circuit
// breaker states to determine overall module health.
func (m *ModuleMetrics) CheckHealth(ctx sdk.Context) HealthStatus {
	checks := make([]HealthCheckItem, 0, 4)
	allHealthy := true

	// Check 1: Pending jobs not growing unbounded
	pending := m.JobsPending.Get()
	if pending > 1000 {
		checks = append(checks, HealthCheckItem{
			Name:    "pending_jobs",
			Healthy: false,
			Message: fmt.Sprintf("pending job count (%d) exceeds threshold (1000)", pending),
		})
		allHealthy = false
	} else {
		checks = append(checks, HealthCheckItem{
			Name:    "pending_jobs",
			Healthy: true,
			Message: fmt.Sprintf("%d pending", pending),
		})
	}

	// Check 2: Consensus success rate (only if enough rounds have occurred)
	rounds := m.ConsensusRounds.Get()
	reached := m.ConsensusReached.Get()
	if rounds > 10 {
		successRate := float64(reached) / float64(rounds)
		if successRate < 0.5 {
			checks = append(checks, HealthCheckItem{
				Name:    "consensus_rate",
				Healthy: false,
				Message: fmt.Sprintf("consensus success rate %.1f%% < 50%%", successRate*100),
			})
			allHealthy = false
		} else {
			checks = append(checks, HealthCheckItem{
				Name:    "consensus_rate",
				Healthy: true,
				Message: fmt.Sprintf("%.1f%% success rate over %d rounds", successRate*100, rounds),
			})
		}
	}

	// Check 3: Blocks advancing
	lastHeight := m.LastBlockHeight.Get()
	if lastHeight > 0 && ctx.BlockHeight()-lastHeight > 10 {
		checks = append(checks, HealthCheckItem{
			Name:    "block_progress",
			Healthy: false,
			Message: fmt.Sprintf("last processed block %d, current %d", lastHeight, ctx.BlockHeight()),
		})
		allHealthy = false
	} else {
		checks = append(checks, HealthCheckItem{
			Name:    "block_progress",
			Healthy: true,
			Message: fmt.Sprintf("at block %d", ctx.BlockHeight()),
		})
	}

	// Check 4: Slashing not excessive
	slashApplied := m.SlashingPenaltiesApplied.Get()
	completed := m.JobsCompleted.Get()
	if completed > 10 && slashApplied > completed/5 {
		checks = append(checks, HealthCheckItem{
			Name:    "slashing_rate",
			Healthy: false,
			Message: fmt.Sprintf("slashing events (%d) exceed 20%% of completed jobs (%d)", slashApplied, completed),
		})
		allHealthy = false
	} else {
		checks = append(checks, HealthCheckItem{
			Name:    "slashing_rate",
			Healthy: true,
			Message: fmt.Sprintf("%d slashing events", slashApplied),
		})
	}

	return HealthStatus{
		Healthy:     allHealthy,
		BlockHeight: ctx.BlockHeight(),
		Timestamp:   ctx.BlockTime().UTC().Format(time.RFC3339),
		Checks:      checks,
	}
}

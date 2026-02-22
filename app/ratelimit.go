package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// =============================================================================
// Rate Limiter Implementation
// =============================================================================

// RateLimiter provides token bucket rate limiting for API endpoints and
// transaction processing. This protects the node from DoS attacks and
// ensures fair resource allocation.
type RateLimiter struct {
	mu sync.RWMutex

	// Global rate limits
	globalBucket *TokenBucket

	// Per-address rate limits
	addressBuckets map[string]*TokenBucket

	// Per-address job submission limits
	jobSubmissionBuckets map[string]*TokenBucket

	// Per-endpoint rate limits
	endpointBuckets map[string]*TokenBucket

	// Configuration
	config RateLimitConfig

	// Metrics
	metrics *RateLimitMetrics
}

// TokenBucket implements the token bucket algorithm for rate limiting.
// Tokens are added at a steady rate up to a maximum capacity.
// Each request consumes one or more tokens.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	lastTime time.Time
}

// RateLimitConfig contains configuration for rate limiting
type RateLimitConfig struct {
	// Global limits
	GlobalRatePerSecond int
	GlobalBurstSize     int

	// Per-address limits
	AddressRatePerSecond int
	AddressBurstSize     int

	// Per-endpoint limits (for expensive operations)
	EndpointRates map[string]EndpointRateConfig

	// Job submission limits
	JobSubmissionRatePerSecond int
	JobSubmissionBurstSize     int

	// Cleanup interval for stale buckets
	CleanupInterval time.Duration

	// Maximum number of tracked addresses (to prevent memory exhaustion)
	MaxTrackedAddresses int
}

// EndpointRateConfig configures rate limiting for a specific endpoint
type EndpointRateConfig struct {
	RatePerSecond int
	BurstSize     int
}

// RateLimitMetrics tracks rate limiting statistics
type RateLimitMetrics struct {
	mu sync.Mutex

	TotalRequests   int64
	AllowedRequests int64
	DeniedRequests  int64

	// Per-address denial counts
	AddressDenials map[string]int64

	// Per-endpoint denial counts
	EndpointDenials map[string]int64
}

const jobSubmissionEndpoint = "/aethelred.pouw.v1.MsgSubmitJob"

// DefaultRateLimitConfig returns production-ready rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		GlobalRatePerSecond: 1000, // 1000 requests/second globally
		GlobalBurstSize:     2000, // Allow short bursts

		AddressRatePerSecond: 100, // 100 requests/second per address
		AddressBurstSize:     200,

		JobSubmissionRatePerSecond: 10, // 10 job submissions/second per address
		JobSubmissionBurstSize:     20,

		EndpointRates: map[string]EndpointRateConfig{
			jobSubmissionEndpoint: {
				RatePerSecond: 10,
				BurstSize:     20,
			},
			"/aethelred.seal.v1.Query/GetSeal": {
				RatePerSecond: 100,
				BurstSize:     200,
			},
			"/aethelred.seal.v1.Query/ListSeals": {
				RatePerSecond: 20, // Expensive query
				BurstSize:     40,
			},
		},

		CleanupInterval:     5 * time.Minute,
		MaxTrackedAddresses: 100000,
	}
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		globalBucket:         NewTokenBucket(float64(config.GlobalBurstSize), float64(config.GlobalRatePerSecond)),
		addressBuckets:       make(map[string]*TokenBucket),
		jobSubmissionBuckets: make(map[string]*TokenBucket),
		endpointBuckets:      make(map[string]*TokenBucket),
		config:               config,
		metrics: &RateLimitMetrics{
			AddressDenials:  make(map[string]int64),
			EndpointDenials: make(map[string]int64),
		},
	}

	// Initialize endpoint buckets
	for endpoint, cfg := range config.EndpointRates {
		rl.endpointBuckets[endpoint] = NewTokenBucket(float64(cfg.BurstSize), float64(cfg.RatePerSecond))
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity, rate float64) *TokenBucket {
	return &TokenBucket{
		tokens:   capacity,
		capacity: capacity,
		rate:     rate,
		lastTime: time.Now(),
	}
}

// Allow checks if a request should be allowed based on rate limits.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(ctx context.Context, address string, endpoint string) bool {
	rl.metrics.mu.Lock()
	rl.metrics.TotalRequests++
	rl.metrics.mu.Unlock()

	// Check global rate limit
	if !rl.globalBucket.Take(1) {
		rl.recordDenial("", endpoint)
		return false
	}

	// Check per-address rate limit
	if address != "" {
		bucket := rl.getOrCreateAddressBucket(address)
		if !bucket.Take(1) {
			rl.recordDenial(address, endpoint)
			return false
		}
	}

	// Check per-endpoint rate limit
	if endpoint != "" {
		rl.mu.RLock()
		bucket, exists := rl.endpointBuckets[endpoint]
		rl.mu.RUnlock()

		if exists && !bucket.Take(1) {
			rl.recordDenial(address, endpoint)
			return false
		}
	}

	rl.metrics.mu.Lock()
	rl.metrics.AllowedRequests++
	rl.metrics.mu.Unlock()

	return true
}

// AllowJobSubmission checks if a job submission should be allowed.
// Job submissions have stricter rate limits.
func (rl *RateLimiter) AllowJobSubmission(ctx context.Context, address string) bool {
	// Check global limit first
	if !rl.globalBucket.Take(1) {
		rl.recordDenial(address, jobSubmissionEndpoint)
		return false
	}

	// Enforce per-address limits as well
	if address != "" {
		bucket := rl.getOrCreateAddressBucket(address)
		if !bucket.Take(1) {
			rl.recordDenial(address, jobSubmissionEndpoint)
			return false
		}
	}

	// Enforce per-endpoint limits if configured
	rl.mu.RLock()
	endpointBucket, exists := rl.endpointBuckets[jobSubmissionEndpoint]
	rl.mu.RUnlock()
	if exists && !endpointBucket.Take(1) {
		rl.recordDenial(address, jobSubmissionEndpoint)
		return false
	}

	// Get or create job submission bucket for this address
	bucket := rl.getOrCreateJobSubmissionBucket(address)

	if !bucket.Take(1) {
		rl.recordDenial(address, jobSubmissionEndpoint)
		return false
	}

	return true
}

// getOrCreateAddressBucket returns or creates a rate limit bucket for an address
func (rl *RateLimiter) getOrCreateAddressBucket(address string) *TokenBucket {
	rl.mu.RLock()
	bucket, exists := rl.addressBuckets[address]
	rl.mu.RUnlock()

	if exists {
		return bucket
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if bucket, exists = rl.addressBuckets[address]; exists {
		return bucket
	}

	// Check if we've hit the max tracked addresses
	if len(rl.addressBuckets) >= rl.config.MaxTrackedAddresses {
		// Evict oldest bucket (simple LRU would be better in production)
		for k := range rl.addressBuckets {
			delete(rl.addressBuckets, k)
			break
		}
	}

	bucket = NewTokenBucket(
		float64(rl.config.AddressBurstSize),
		float64(rl.config.AddressRatePerSecond),
	)
	rl.addressBuckets[address] = bucket

	return bucket
}

// getOrCreateJobSubmissionBucket returns or creates a bucket for job submissions.
func (rl *RateLimiter) getOrCreateJobSubmissionBucket(address string) *TokenBucket {
	key := "job:" + address

	rl.mu.RLock()
	bucket, exists := rl.jobSubmissionBuckets[key]
	rl.mu.RUnlock()

	if exists {
		return bucket
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if bucket, exists = rl.jobSubmissionBuckets[key]; exists {
		return bucket
	}

	if len(rl.jobSubmissionBuckets) >= rl.config.MaxTrackedAddresses {
		for k := range rl.jobSubmissionBuckets {
			delete(rl.jobSubmissionBuckets, k)
			break
		}
	}

	bucket = NewTokenBucket(
		float64(rl.config.JobSubmissionBurstSize),
		float64(rl.config.JobSubmissionRatePerSecond),
	)
	rl.jobSubmissionBuckets[key] = bucket

	return bucket
}

// recordDenial records a rate limit denial in metrics
func (rl *RateLimiter) recordDenial(address, endpoint string) {
	rl.metrics.mu.Lock()
	defer rl.metrics.mu.Unlock()

	rl.metrics.DeniedRequests++

	if address != "" {
		rl.metrics.AddressDenials[address]++
	}
	if endpoint != "" {
		rl.metrics.EndpointDenials[endpoint]++
	}
}

// cleanupLoop periodically cleans up stale rate limit buckets
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup removes stale address buckets
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	staleThreshold := rl.config.CleanupInterval * 2

	for address, bucket := range rl.addressBuckets {
		bucket.mu.Lock()
		if now.Sub(bucket.lastTime) > staleThreshold {
			delete(rl.addressBuckets, address)
		}
		bucket.mu.Unlock()
	}

	for address, bucket := range rl.jobSubmissionBuckets {
		bucket.mu.Lock()
		if now.Sub(bucket.lastTime) > staleThreshold {
			delete(rl.jobSubmissionBuckets, address)
		}
		bucket.mu.Unlock()
	}
}

// Take attempts to consume n tokens from the bucket.
// Returns true if tokens were available, false otherwise.
func (tb *TokenBucket) Take(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.lastTime = now

	// Add tokens based on elapsed time
	tb.tokens = min(tb.capacity, tb.tokens+elapsed*tb.rate)

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}

	return false
}

// GetMetrics returns the current rate limit metrics
func (rl *RateLimiter) GetMetrics() RateLimitMetrics {
	rl.metrics.mu.Lock()
	defer rl.metrics.mu.Unlock()

	// Return a copy
	return RateLimitMetrics{
		TotalRequests:   rl.metrics.TotalRequests,
		AllowedRequests: rl.metrics.AllowedRequests,
		DeniedRequests:  rl.metrics.DeniedRequests,
		AddressDenials:  copyMap(rl.metrics.AddressDenials),
		EndpointDenials: copyMap(rl.metrics.EndpointDenials),
	}
}

func copyMap(m map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// Ante Handler Decorator for Rate Limiting
// =============================================================================

// RateLimitDecorator wraps an ante handler with rate limiting
type RateLimitDecorator struct {
	rateLimiter *RateLimiter
}

// NewRateLimitDecorator creates a new rate limit decorator
func NewRateLimitDecorator(rateLimiter *RateLimiter) RateLimitDecorator {
	return RateLimitDecorator{rateLimiter: rateLimiter}
}

// AnteHandle implements the AnteDecorator interface
func (rld RateLimitDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	// Skip rate limiting for simulations
	if simulate {
		return next(ctx, tx, simulate)
	}

	// Skip if rate limiter not configured
	if rld.rateLimiter == nil {
		return next(ctx, tx, simulate)
	}

	// Get the sender address from the transaction signatures
	// In Cosmos SDK v0.50+, we need to get signers differently
	sigTx, ok := tx.(interface {
		GetSigners() ([][]byte, error)
	})
	if !ok {
		return next(ctx, tx, simulate)
	}

	signers, err := sigTx.GetSigners()
	if err != nil || len(signers) == 0 {
		return next(ctx, tx, simulate)
	}

	address := sdk.AccAddress(signers[0]).String()

	for _, msg := range tx.GetMsgs() {
		endpoint := sdk.MsgTypeURL(msg)

		// Apply stricter limits for job submissions.
		if endpoint == jobSubmissionEndpoint {
			if !rld.rateLimiter.AllowJobSubmission(ctx.Context(), address) {
				return ctx, fmt.Errorf("rate limit exceeded for job submission by %s", address)
			}
			continue
		}

		if !rld.rateLimiter.Allow(ctx.Context(), address, endpoint) {
			return ctx, fmt.Errorf("rate limit exceeded for %s by %s", endpoint, address)
		}
	}

	return next(ctx, tx, simulate)
}

// =============================================================================
// Integration with AethelredApp
// =============================================================================

// InitRateLimiter initializes the rate limiter for the application
func (app *AethelredApp) InitRateLimiter() {
	config := DefaultRateLimitConfig()
	app.rateLimiter = NewRateLimiter(config)

	app.Logger().Info("Rate limiter initialized",
		"global_rate", config.GlobalRatePerSecond,
		"address_rate", config.AddressRatePerSecond,
		"job_rate", config.JobSubmissionRatePerSecond,
	)
}

// rateLimiter is the application's rate limiter instance
// This will be added to the AethelredApp struct
var globalRateLimiter *RateLimiter

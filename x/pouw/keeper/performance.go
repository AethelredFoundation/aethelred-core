package keeper

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// WEEK 35-36: Performance Tuning & Protocol Freeze
// ---------------------------------------------------------------------------
//
// This file implements:
//   1. Protocol freeze mechanism — governance-controlled freeze that gates
//      state-mutating transactions while allowing queries and governance.
//   2. Block processing budget — enforces wall-clock time limits on EndBlock
//      operations to prevent block production stalls.
//   3. Performance profile — tuned scheduler/consensus config optimized for
//      mainnet throughput targets.
//   4. Protocol version manifest — immutable snapshot of the frozen protocol
//      specification for reproducibility and audit.
//   5. SLA enforcement — validator performance SLAs with degradation alerts.
//
// Design principles:
//   - All freeze state is on-chain (governance-mutable only)
//   - Performance tuning is deterministic and reproducible
//   - Block budgets use wall-clock time and are non-consensus-breaking
//   - Protocol manifest is a pure function of module state
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section 1: Protocol Freeze
// ---------------------------------------------------------------------------

// ProtocolFreezeState represents the on-chain freeze status.
type ProtocolFreezeState struct {
	// IsFrozen indicates whether the protocol is currently frozen.
	IsFrozen bool

	// FreezeHeight is the block height at which the freeze was activated.
	FreezeHeight int64

	// FreezeReason documents why the protocol was frozen.
	FreezeReason string

	// FrozenBy is the governance authority that initiated the freeze.
	FrozenBy string

	// AllowedOperations lists the message types that remain functional during freeze.
	// By default: queries, governance param updates, and freeze/unfreeze.
	AllowedOperations []string

	// ProtocolVersion is the version string locked at freeze time.
	ProtocolVersion string
}

// NewProtocolFreeze creates a frozen state at the given block height.
func NewProtocolFreeze(height int64, reason, authority, version string) *ProtocolFreezeState {
	return &ProtocolFreezeState{
		IsFrozen:     true,
		FreezeHeight: height,
		FreezeReason: reason,
		FrozenBy:     authority,
		AllowedOperations: []string{
			"QueryParams",
			"QueryJob",
			"QuerySeals",
			"UpdateParams",
			"ProtocolFreeze",
			"ProtocolUnfreeze",
		},
		ProtocolVersion: version,
	}
}

// IsOperationAllowed checks whether a given operation is permitted under freeze.
func (pf *ProtocolFreezeState) IsOperationAllowed(operation string) bool {
	if !pf.IsFrozen {
		return true
	}
	for _, allowed := range pf.AllowedOperations {
		if allowed == operation {
			return true
		}
	}
	return false
}

// Unfreeze lifts the protocol freeze.
func (pf *ProtocolFreezeState) Unfreeze() {
	pf.IsFrozen = false
}

// CheckFreezeGate returns an error if the protocol is frozen and the operation
// is not in the allow list. This is intended to be called at the top of every
// state-mutating message handler.
func CheckFreezeGate(freeze *ProtocolFreezeState, operation string) error {
	if freeze == nil || !freeze.IsFrozen {
		return nil
	}
	if freeze.IsOperationAllowed(operation) {
		return nil
	}
	return fmt.Errorf(
		"protocol frozen at height %d: operation %q is not permitted during freeze (reason: %s)",
		freeze.FreezeHeight, operation, freeze.FreezeReason,
	)
}

// ---------------------------------------------------------------------------
// Section 2: Block Processing Budget
// ---------------------------------------------------------------------------

// BlockBudget enforces wall-clock time limits on per-block operations.
// It is used by EndBlock to ensure that invariant checks, consistency
// maintenance, and metric emission do not stall block production.
type BlockBudget struct {
	mu          sync.Mutex
	total       time.Duration
	spent       time.Duration
	taskTimings []TaskTiming
	exceeded    bool
}

// TaskTiming records how long a specific task took within the block budget.
type TaskTiming struct {
	Name     string
	Duration time.Duration
	Skipped  bool
}

// NewBlockBudget creates a block budget with the given total time limit.
func NewBlockBudget(total time.Duration) *BlockBudget {
	return &BlockBudget{
		total:       total,
		taskTimings: make([]TaskTiming, 0, 8),
	}
}

// DefaultBlockBudget returns a block budget with a 200ms limit.
// With 6-second block times, this reserves ~3% of block time for housekeeping.
func DefaultBlockBudget() *BlockBudget {
	return NewBlockBudget(200 * time.Millisecond)
}

// Remaining returns how much budget is left.
func (bb *BlockBudget) Remaining() time.Duration {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	r := bb.total - bb.spent
	if r < 0 {
		return 0
	}
	return r
}

// HasBudget returns true if there is time remaining in the budget.
func (bb *BlockBudget) HasBudget() bool {
	return bb.Remaining() > 0
}

// RunTask executes a named task within the budget. If no budget remains,
// the task is skipped (recorded as Skipped=true). Returns the task duration
// and whether it was actually executed.
func (bb *BlockBudget) RunTask(name string, fn func()) (time.Duration, bool) {
	bb.mu.Lock()
	if bb.spent >= bb.total {
		bb.taskTimings = append(bb.taskTimings, TaskTiming{
			Name:    name,
			Skipped: true,
		})
		bb.exceeded = true
		bb.mu.Unlock()
		return 0, false
	}
	bb.mu.Unlock()

	start := time.Now()
	fn()
	elapsed := time.Since(start)

	bb.mu.Lock()
	bb.spent += elapsed
	bb.taskTimings = append(bb.taskTimings, TaskTiming{
		Name:     name,
		Duration: elapsed,
		Skipped:  false,
	})
	if bb.spent > bb.total {
		bb.exceeded = true
	}
	bb.mu.Unlock()

	return elapsed, true
}

// Summary returns all task timings and whether the budget was exceeded.
func (bb *BlockBudget) Summary() ([]TaskTiming, bool) {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	result := make([]TaskTiming, len(bb.taskTimings))
	copy(result, bb.taskTimings)
	return result, bb.exceeded
}

// TotalSpent returns the total time spent across all tasks.
func (bb *BlockBudget) TotalSpent() time.Duration {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	return bb.spent
}

// ---------------------------------------------------------------------------
// Section 3: Performance Profile
// ---------------------------------------------------------------------------

// PerformanceProfile defines a named set of tuning parameters for the module.
// Profiles are selected based on network conditions and phase (testnet, mainnet).
type PerformanceProfile struct {
	Name        string
	Description string

	// Scheduler tuning
	MaxJobsPerBlock       int
	MaxJobsPerValidator   int
	PriorityBoostPerBlock int64
	MaxRetries            int

	// Consensus tuning
	MinValidatorsRequired  int
	ConsensusTimeoutBlocks int64
	VoteExtensionMaxBytes  int

	// Resource limits
	MaxPendingJobs   int64
	MaxBlockBudgetMs int64
	MaxQueryPageSize int

	// SLA targets (in blocks)
	TargetJobCompletionBlocks int64
	MaxJobCompletionBlocks    int64
}

// TestnetProfile returns conservative settings for testnet operation.
func TestnetProfile() PerformanceProfile {
	return PerformanceProfile{
		Name:        "testnet",
		Description: "Conservative testnet settings with relaxed SLAs",

		MaxJobsPerBlock:       10,
		MaxJobsPerValidator:   3,
		PriorityBoostPerBlock: 1,
		MaxRetries:            5,

		MinValidatorsRequired:  3,
		ConsensusTimeoutBlocks: 100,
		VoteExtensionMaxBytes:  65536,

		MaxPendingJobs:   500,
		MaxBlockBudgetMs: 500,
		MaxQueryPageSize: 100,

		TargetJobCompletionBlocks: 20,
		MaxJobCompletionBlocks:    100,
	}
}

// MainnetProfile returns optimized settings for mainnet production.
func MainnetProfile() PerformanceProfile {
	return PerformanceProfile{
		Name:        "mainnet",
		Description: "Production-optimized mainnet settings with strict SLAs",

		MaxJobsPerBlock:       25,
		MaxJobsPerValidator:   5,
		PriorityBoostPerBlock: 2,
		MaxRetries:            3,

		MinValidatorsRequired:  5,
		ConsensusTimeoutBlocks: 50,
		VoteExtensionMaxBytes:  32768,

		MaxPendingJobs:   1000,
		MaxBlockBudgetMs: 200,
		MaxQueryPageSize: 50,

		TargetJobCompletionBlocks: 10,
		MaxJobCompletionBlocks:    50,
	}
}

// StressTestProfile returns aggressive settings for stress testing.
func StressTestProfile() PerformanceProfile {
	return PerformanceProfile{
		Name:        "stress",
		Description: "Aggressive stress test settings for load testing",

		MaxJobsPerBlock:       100,
		MaxJobsPerValidator:   10,
		PriorityBoostPerBlock: 5,
		MaxRetries:            1,

		MinValidatorsRequired:  3,
		ConsensusTimeoutBlocks: 20,
		VoteExtensionMaxBytes:  131072,

		MaxPendingJobs:   5000,
		MaxBlockBudgetMs: 1000,
		MaxQueryPageSize: 200,

		TargetJobCompletionBlocks: 5,
		MaxJobCompletionBlocks:    20,
	}
}

// ToSchedulerConfig converts the profile to a SchedulerConfig.
func (pp PerformanceProfile) ToSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		MaxJobsPerBlock:       pp.MaxJobsPerBlock,
		MaxJobsPerValidator:   pp.MaxJobsPerValidator,
		JobTimeoutBlocks:      pp.ConsensusTimeoutBlocks,
		MinValidatorsRequired: pp.MinValidatorsRequired,
		PriorityBoostPerBlock: pp.PriorityBoostPerBlock,
		MaxRetries:            pp.MaxRetries,
	}
}

// ValidateProfile ensures all profile parameters are within acceptable bounds.
func (pp PerformanceProfile) ValidateProfile() error {
	if pp.MaxJobsPerBlock < 1 || pp.MaxJobsPerBlock > 1000 {
		return fmt.Errorf("MaxJobsPerBlock must be in [1, 1000], got %d", pp.MaxJobsPerBlock)
	}
	if pp.MaxJobsPerValidator < 1 || pp.MaxJobsPerValidator > 50 {
		return fmt.Errorf("MaxJobsPerValidator must be in [1, 50], got %d", pp.MaxJobsPerValidator)
	}
	if pp.MinValidatorsRequired < 1 || pp.MinValidatorsRequired > 100 {
		return fmt.Errorf("MinValidatorsRequired must be in [1, 100], got %d", pp.MinValidatorsRequired)
	}
	if pp.ConsensusTimeoutBlocks < 5 {
		return fmt.Errorf("ConsensusTimeoutBlocks must be >= 5, got %d", pp.ConsensusTimeoutBlocks)
	}
	if pp.MaxPendingJobs < 10 {
		return fmt.Errorf("MaxPendingJobs must be >= 10, got %d", pp.MaxPendingJobs)
	}
	if pp.MaxBlockBudgetMs < 50 || pp.MaxBlockBudgetMs > 5000 {
		return fmt.Errorf("MaxBlockBudgetMs must be in [50, 5000], got %d", pp.MaxBlockBudgetMs)
	}
	if pp.TargetJobCompletionBlocks < 1 {
		return fmt.Errorf("TargetJobCompletionBlocks must be >= 1, got %d", pp.TargetJobCompletionBlocks)
	}
	if pp.MaxJobCompletionBlocks < pp.TargetJobCompletionBlocks {
		return fmt.Errorf("MaxJobCompletionBlocks (%d) must be >= TargetJobCompletionBlocks (%d)",
			pp.MaxJobCompletionBlocks, pp.TargetJobCompletionBlocks)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Section 4: Protocol Version Manifest
// ---------------------------------------------------------------------------

// ProtocolManifest is an immutable snapshot of the protocol specification
// at a given point in time. It captures all version-relevant information
// needed to reproduce the exact behavior of the chain.
type ProtocolManifest struct {
	// Identity
	ChainID       string
	ModuleName    string
	ModuleVersion uint64
	ProtocolName  string

	// Timestamps
	GeneratedAt string
	BlockHeight int64

	// Parameters (frozen values)
	FrozenParams *types.Params

	// Component versions
	Components []ComponentVersion

	// Invariant checksums
	InvariantCount int
	InvariantsPass bool

	// Performance profile
	ActiveProfile string

	// Security posture
	AllowSimulated     bool
	ConsensusThreshold int64
	MinValidators      int64

	// State statistics
	TotalJobs        uint64
	TotalValidators  int
	RegisteredModels int
}

// ComponentVersion describes the version of a subcomponent.
type ComponentVersion struct {
	Name    string
	Version string
	Status  string // "active", "deprecated", "frozen"
}

// BuildProtocolManifest creates a manifest from the current chain state.
func BuildProtocolManifest(ctx sdk.Context, k Keeper) *ProtocolManifest {
	params, _ := k.GetParams(ctx)

	// Count state objects
	totalJobs, _ := k.JobCount.Get(ctx)

	validatorCount := 0
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, _ types.ValidatorStats) (bool, error) {
		validatorCount++
		return false, nil
	})

	modelCount := 0
	_ = k.RegisteredModels.Walk(ctx, nil, func(_ string, _ types.RegisteredModel) (bool, error) {
		modelCount++
		return false, nil
	})

	// Run invariants
	invariants := AllInvariants(k)
	_, broken := invariants(ctx)

	manifest := &ProtocolManifest{
		ChainID:       ctx.ChainID(),
		ModuleName:    types.ModuleName,
		ModuleVersion: ModuleConsensusVersion,
		ProtocolName:  "Aethelred Sovereign L1 — Proof-of-Useful-Work",

		GeneratedAt: ctx.BlockTime().UTC().Format(time.RFC3339),
		BlockHeight: ctx.BlockHeight(),

		FrozenParams: params,

		Components: []ComponentVersion{
			{Name: "pouw/keeper", Version: "1.0.0", Status: "frozen"},
			{Name: "pouw/consensus", Version: "1.0.0", Status: "frozen"},
			{Name: "pouw/scheduler", Version: "1.0.0", Status: "frozen"},
			{Name: "pouw/governance", Version: "1.0.0", Status: "frozen"},
			{Name: "pouw/evidence", Version: "1.0.0", Status: "frozen"},
			{Name: "pouw/metrics", Version: "1.0.0", Status: "active"},
			{Name: "seal/keeper", Version: "1.0.0", Status: "frozen"},
			{Name: "verify/keeper", Version: "1.0.0", Status: "frozen"},
			{Name: "validator/slashing", Version: "1.0.0", Status: "frozen"},
		},

		InvariantCount: 7,
		InvariantsPass: !broken,

		ActiveProfile: "mainnet",

		TotalJobs:        totalJobs,
		TotalValidators:  validatorCount,
		RegisteredModels: modelCount,
	}

	if params != nil {
		manifest.AllowSimulated = params.AllowSimulated
		manifest.ConsensusThreshold = params.ConsensusThreshold
		manifest.MinValidators = params.MinValidators
	}

	return manifest
}

// RenderManifest produces a human-readable manifest document.
func (m *ProtocolManifest) RenderManifest() string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║            PROTOCOL VERSION MANIFEST                        ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Protocol: %s\n", m.ProtocolName))
	sb.WriteString(fmt.Sprintf("Chain ID: %s\n", m.ChainID))
	sb.WriteString(fmt.Sprintf("Module:   %s v%d\n", m.ModuleName, m.ModuleVersion))
	sb.WriteString(fmt.Sprintf("Generated: %s (Block %d)\n\n", m.GeneratedAt, m.BlockHeight))

	sb.WriteString("─── FROZEN PARAMETERS ─────────────────────────────────────────\n")
	if m.FrozenParams != nil {
		sb.WriteString(fmt.Sprintf("  ConsensusThreshold:    %d%%\n", m.FrozenParams.ConsensusThreshold))
		sb.WriteString(fmt.Sprintf("  MinValidators:         %d\n", m.FrozenParams.MinValidators))
		sb.WriteString(fmt.Sprintf("  JobTimeoutBlocks:      %d\n", m.FrozenParams.JobTimeoutBlocks))
		sb.WriteString(fmt.Sprintf("  MaxJobsPerBlock:       %d\n", m.FrozenParams.MaxJobsPerBlock))
		sb.WriteString(fmt.Sprintf("  BaseJobFee:            %s\n", m.FrozenParams.BaseJobFee))
		sb.WriteString(fmt.Sprintf("  VerificationReward:    %s\n", m.FrozenParams.VerificationReward))
		sb.WriteString(fmt.Sprintf("  SlashingPenalty:       %s\n", m.FrozenParams.SlashingPenalty))
		sb.WriteString(fmt.Sprintf("  AllowedProofTypes:     %v\n", m.FrozenParams.AllowedProofTypes))
		sb.WriteString(fmt.Sprintf("  RequireTeeAttestation: %v\n", m.FrozenParams.RequireTeeAttestation))
		sb.WriteString(fmt.Sprintf("  AllowZkmlFallback:     %v\n", m.FrozenParams.AllowZkmlFallback))
		sb.WriteString(fmt.Sprintf("  AllowSimulated:        %v\n", m.FrozenParams.AllowSimulated))
	}

	sb.WriteString("\n─── COMPONENT VERSIONS ────────────────────────────────────────\n")
	for _, c := range m.Components {
		sb.WriteString(fmt.Sprintf("  %-25s %s  [%s]\n", c.Name, c.Version, c.Status))
	}

	sb.WriteString("\n─── SECURITY POSTURE ──────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  AllowSimulated:     %v\n", m.AllowSimulated))
	sb.WriteString(fmt.Sprintf("  ConsensusThreshold: %d%% (BFT: >66%%)\n", m.ConsensusThreshold))
	sb.WriteString(fmt.Sprintf("  MinValidators:      %d\n", m.MinValidators))
	invStatus := "PASS"
	if !m.InvariantsPass {
		invStatus = "FAIL"
	}
	sb.WriteString(fmt.Sprintf("  Invariants:         %d checks — %s\n", m.InvariantCount, invStatus))

	sb.WriteString("\n─── STATE STATISTICS ──────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Total Jobs:          %d\n", m.TotalJobs))
	sb.WriteString(fmt.Sprintf("  Total Validators:    %d\n", m.TotalValidators))
	sb.WriteString(fmt.Sprintf("  Registered Models:   %d\n", m.RegisteredModels))

	sb.WriteString("\n─── PERFORMANCE PROFILE ───────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Active Profile: %s\n", m.ActiveProfile))

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// ---------------------------------------------------------------------------
// Section 5: SLA Enforcement
// ---------------------------------------------------------------------------

// ValidatorSLA defines performance expectations for validators.
type ValidatorSLA struct {
	// MinUptimePercent is the minimum uptime percentage (0-100).
	MinUptimePercent int

	// MaxResponseBlocks is the maximum blocks allowed for job completion.
	MaxResponseBlocks int64

	// MinReputationScore is the minimum acceptable reputation.
	MinReputationScore int64

	// MaxConsecutiveMisses is the max consecutive missed blocks before alert.
	MaxConsecutiveMisses int64
}

// DefaultValidatorSLA returns the standard mainnet SLA.
func DefaultValidatorSLA() ValidatorSLA {
	return ValidatorSLA{
		MinUptimePercent:     95,
		MaxResponseBlocks:    20,
		MinReputationScore:   40,
		MaxConsecutiveMisses: 10,
	}
}

// SLAViolation describes a specific SLA breach.
type SLAViolation struct {
	ValidatorAddr string
	Metric        string
	Expected      string
	Actual        string
	Severity      string // "warning", "critical"
}

// CheckValidatorSLA evaluates a validator against the SLA requirements.
func CheckValidatorSLA(sla ValidatorSLA, stats types.ValidatorStats) []SLAViolation {
	var violations []SLAViolation

	// Check reputation score
	if stats.ReputationScore < sla.MinReputationScore {
		violations = append(violations, SLAViolation{
			ValidatorAddr: stats.ValidatorAddress,
			Metric:        "reputation_score",
			Expected:      fmt.Sprintf(">= %d", sla.MinReputationScore),
			Actual:        fmt.Sprintf("%d", stats.ReputationScore),
			Severity:      severityForReputation(stats.ReputationScore),
		})
	}

	// Check failure rate (only if enough jobs processed)
	if stats.TotalJobsProcessed >= 10 {
		failRate := float64(stats.FailedJobs) / float64(stats.TotalJobsProcessed) * 100
		maxFailRate := float64(100 - sla.MinUptimePercent)
		if failRate > maxFailRate {
			violations = append(violations, SLAViolation{
				ValidatorAddr: stats.ValidatorAddress,
				Metric:        "failure_rate",
				Expected:      fmt.Sprintf("<= %.1f%%", maxFailRate),
				Actual:        fmt.Sprintf("%.1f%%", failRate),
				Severity:      severityForFailRate(failRate),
			})
		}
	}

	// Check slashing events
	if stats.SlashingEvents > 3 {
		violations = append(violations, SLAViolation{
			ValidatorAddr: stats.ValidatorAddress,
			Metric:        "slashing_events",
			Expected:      "<= 3",
			Actual:        fmt.Sprintf("%d", stats.SlashingEvents),
			Severity:      "critical",
		})
	}

	return violations
}

func severityForReputation(score int64) string {
	if score < 20 {
		return "critical"
	}
	return "warning"
}

func severityForFailRate(rate float64) string {
	if rate > 20 {
		return "critical"
	}
	return "warning"
}

// RunSLACheck evaluates all validators against the SLA and returns violations.
func RunSLACheck(ctx sdk.Context, k Keeper, sla ValidatorSLA) []SLAViolation {
	var allViolations []SLAViolation

	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, stats types.ValidatorStats) (bool, error) {
		violations := CheckValidatorSLA(sla, stats)
		allViolations = append(allViolations, violations...)
		return false, nil
	})

	// Sort by severity (critical first)
	sort.Slice(allViolations, func(i, j int) bool {
		if allViolations[i].Severity != allViolations[j].Severity {
			return allViolations[i].Severity == "critical"
		}
		return allViolations[i].ValidatorAddr < allViolations[j].ValidatorAddr
	})

	return allViolations
}

// ---------------------------------------------------------------------------
// Section 6: Performance Benchmarks (testable functions)
// ---------------------------------------------------------------------------

// BenchmarkResult captures the result of a single benchmark operation.
type BenchmarkResult struct {
	Name       string
	Iterations int
	TotalTime  time.Duration
	AvgTime    time.Duration
	MinTime    time.Duration
	MaxTime    time.Duration
	P95Time    time.Duration
	P99Time    time.Duration
	OpsPerSec  float64
}

// RunInvariantBenchmark measures the cost of running all invariants.
func RunInvariantBenchmark(ctx sdk.Context, k Keeper, iterations int) BenchmarkResult {
	if iterations < 1 {
		iterations = 1
	}

	invariants := AllInvariants(k)
	durations := make([]time.Duration, iterations)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		invariants(ctx)
		durations[i] = time.Since(start)
	}

	return computeBenchmarkResult("AllInvariants", durations)
}

// RunParamValidationBenchmark measures parameter validation cost.
func RunParamValidationBenchmark(iterations int) BenchmarkResult {
	if iterations < 1 {
		iterations = 1
	}

	params := types.DefaultParams()
	durations := make([]time.Duration, iterations)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		ValidateParams(params)
		durations[i] = time.Since(start)
	}

	return computeBenchmarkResult("ValidateParams", durations)
}

// RunConsistencyCheckBenchmark measures end-block consistency check cost.
func RunConsistencyCheckBenchmark(ctx sdk.Context, k Keeper, iterations int) BenchmarkResult {
	if iterations < 1 {
		iterations = 1
	}

	durations := make([]time.Duration, iterations)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		EndBlockConsistencyChecks(ctx, k)
		durations[i] = time.Since(start)
	}

	return computeBenchmarkResult("EndBlockConsistencyChecks", durations)
}

// RunPerformanceScoreBenchmark measures validator performance scoring cost.
func RunPerformanceScoreBenchmark(iterations int) BenchmarkResult {
	if iterations < 1 {
		iterations = 1
	}

	metrics := PerformanceMetrics{
		ReputationScore:   80,
		JobsCompleted:     500,
		JobsFailed:        10,
		AvgResponseBlocks: 3.0,
		ConsecutiveMisses: 0,
		IsOnline:          true,
	}

	durations := make([]time.Duration, iterations)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		PerformanceScore(metrics)
		durations[i] = time.Since(start)
	}

	return computeBenchmarkResult("PerformanceScore", durations)
}

func computeBenchmarkResult(name string, durations []time.Duration) BenchmarkResult {
	n := len(durations)
	if n == 0 {
		return BenchmarkResult{Name: name}
	}

	var total time.Duration
	minD := durations[0]
	maxD := durations[0]

	for _, d := range durations {
		total += d
		if d < minD {
			minD = d
		}
		if d > maxD {
			maxD = d
		}
	}

	avg := total / time.Duration(n)
	sorted := make([]time.Duration, n)
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p95 := percentileDuration(sorted, 95)
	p99 := percentileDuration(sorted, 99)
	opsPerSec := float64(0)
	if avg > 0 {
		opsPerSec = float64(time.Second) / float64(avg)
	}

	return BenchmarkResult{
		Name:       name,
		Iterations: n,
		TotalTime:  total,
		AvgTime:    avg,
		MinTime:    minD,
		MaxTime:    maxD,
		P95Time:    p95,
		P99Time:    p99,
		OpsPerSec:  opsPerSec,
	}
}

func percentileDuration(sorted []time.Duration, p int) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := int(math.Ceil((float64(p) / 100.0) * float64(n)))
	idx := rank - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

// ---------------------------------------------------------------------------
// Section 7: Comprehensive Performance Report
// ---------------------------------------------------------------------------

// PerformanceReport aggregates all performance analysis results.
type PerformanceReport struct {
	// Identity
	ChainID     string
	BlockHeight int64
	GeneratedAt string

	// Benchmark results
	Benchmarks []BenchmarkResult
	// Baseline violations
	BenchmarkViolations []BenchmarkViolation

	// SLA status
	SLAViolations []SLAViolation

	// Block budget analysis
	BlockBudgetMs     int64
	BudgetUtilization float64 // 0.0 - 1.0

	// Protocol freeze status
	FreezeState *ProtocolFreezeState

	// Active performance profile
	ActiveProfile PerformanceProfile

	// Readiness
	IsPerformanceReady bool
}

// RunPerformanceTuningReport generates a comprehensive performance report.
func RunPerformanceTuningReport(ctx sdk.Context, k Keeper) *PerformanceReport {
	profile := MainnetProfile()

	// Run benchmarks
	benchmarks := []BenchmarkResult{
		RunInvariantBenchmark(ctx, k, 100),
		RunParamValidationBenchmark(1000),
		RunConsistencyCheckBenchmark(ctx, k, 100),
		RunPerformanceScoreBenchmark(10000),
	}
	baselines := DefaultBenchmarkBaselines()
	benchmarkViolations := EvaluateBenchmarkBaselines(benchmarks, baselines)

	// Run SLA check
	sla := DefaultValidatorSLA()
	violations := RunSLACheck(ctx, k, sla)

	// Test block budget
	budget := DefaultBlockBudget()
	budget.RunTask("invariants", func() {
		AllInvariants(k)(ctx)
	})
	budget.RunTask("consistency_checks", func() {
		EndBlockConsistencyChecks(ctx, k)
	})
	budget.RunTask("param_validation", func() {
		params, _ := k.GetParams(ctx)
		if params != nil {
			ValidateParams(params)
		}
	})

	spent := budget.TotalSpent()
	budgetMs := profile.MaxBlockBudgetMs
	utilization := float64(0)
	if budgetMs > 0 {
		utilization = float64(spent.Milliseconds()) / float64(budgetMs)
	}

	// Determine readiness
	ready := true
	if len(benchmarkViolations) > 0 {
		ready = false
	}
	// No critical SLA violations
	for _, v := range violations {
		if v.Severity == "critical" {
			ready = false
		}
	}
	// Budget utilization under 80%
	if utilization > 0.8 {
		ready = false
	}

	return &PerformanceReport{
		ChainID:             ctx.ChainID(),
		BlockHeight:         ctx.BlockHeight(),
		GeneratedAt:         ctx.BlockTime().UTC().Format(time.RFC3339),
		Benchmarks:          benchmarks,
		BenchmarkViolations: benchmarkViolations,
		SLAViolations:       violations,
		BlockBudgetMs:       budgetMs,
		BudgetUtilization:   utilization,
		ActiveProfile:       profile,
		IsPerformanceReady:  ready,
	}
}

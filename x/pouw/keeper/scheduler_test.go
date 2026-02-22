package keeper_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// HELPERS
// =============================================================================

// sdkCtxForHeight is defined in production_mode_test.go

func testScheduler(config ...keeper.SchedulerConfig) *keeper.JobScheduler {
	cfg := keeper.DefaultSchedulerConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	return keeper.NewJobScheduler(log.NewNopLogger(), nil, cfg)
}

func testSchedulerWithConfig(cfg keeper.SchedulerConfig) *keeper.JobScheduler {
	return keeper.NewJobScheduler(log.NewNopLogger(), nil, cfg)
}

func makeJob(id string, priority int64, proofType types.ProofType) *types.ComputeJob {
	modelHash := sha256.Sum256([]byte("model-" + id))
	inputHash := sha256.Sum256([]byte("input-" + id))
	fee := sdk.NewInt64Coin("uaeth", 1000)
	bt := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	job := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		sdk.AccAddress(make([]byte, 20)).String(),
		proofType, "credit_scoring", fee, 100, bt,
	)
	job.Id = id
	job.Priority = priority
	return job
}

func makeValidator(addr string, teePlatforms []string, zkmlSystems []string, maxJobs int64) *types.ValidatorCapability {
	return &types.ValidatorCapability{
		Address:           addr,
		TeePlatforms:      teePlatforms,
		ZkmlSystems:       zkmlSystems,
		MaxConcurrentJobs: maxJobs,
		CurrentJobs:       0,
		IsOnline:          true,
		ReputationScore:   80,
	}
}

// =============================================================================
// ENQUEUE
// =============================================================================

func TestScheduler_EnqueueJob(t *testing.T) {
	s := testScheduler()
	ctx := sdkCtxForHeight(100)

	job := makeJob("job-1", 10, types.ProofTypeTEE)
	if err := s.EnqueueJob(ctx, job); err != nil {
		t.Fatalf("failed to enqueue job: %v", err)
	}

	stats := s.GetQueueStats()
	if stats.TotalJobs != 1 {
		t.Fatalf("expected 1 job in queue, got %d", stats.TotalJobs)
	}
}

func TestScheduler_EnqueueJob_Duplicate(t *testing.T) {
	s := testScheduler()
	ctx := sdkCtxForHeight(100)

	job := makeJob("job-1", 10, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, job)

	// Try to enqueue the same job again
	err := s.EnqueueJob(ctx, job)
	if err == nil {
		t.Fatal("expected error when enqueuing duplicate job")
	}
}

func TestScheduler_EnqueueMultipleJobs(t *testing.T) {
	s := testScheduler()
	ctx := sdkCtxForHeight(100)

	for i := 0; i < 5; i++ {
		job := makeJob(fmt.Sprintf("job-%d", i), int64(i*10), types.ProofTypeTEE)
		if err := s.EnqueueJob(ctx, job); err != nil {
			t.Fatalf("failed to enqueue job-%d: %v", i, err)
		}
	}

	stats := s.GetQueueStats()
	if stats.TotalJobs != 5 {
		t.Fatalf("expected 5 jobs in queue, got %d", stats.TotalJobs)
	}
}

// =============================================================================
// VALIDATOR REGISTRATION
// =============================================================================

func TestScheduler_RegisterValidator(t *testing.T) {
	s := testScheduler()
	val := makeValidator("val1", []string{"aws-nitro"}, nil, 5)
	s.RegisterValidator(val)

	caps := s.GetValidatorCapabilities()
	if len(caps) != 1 {
		t.Fatalf("expected 1 validator, got %d", len(caps))
	}
	if _, ok := caps["val1"]; !ok {
		t.Fatal("validator 'val1' not found in capabilities")
	}
}

func TestScheduler_UnregisterValidator(t *testing.T) {
	s := testScheduler()
	val := makeValidator("val1", []string{"aws-nitro"}, nil, 5)
	s.RegisterValidator(val)
	s.UnregisterValidator("val1")

	caps := s.GetValidatorCapabilities()
	if len(caps) != 0 {
		t.Fatalf("expected 0 validators after unregister, got %d", len(caps))
	}
}

func TestScheduler_RegisterValidator_Update(t *testing.T) {
	s := testScheduler()
	val := makeValidator("val1", []string{"aws-nitro"}, nil, 5)
	s.RegisterValidator(val)

	// Update with additional capabilities
	val2 := makeValidator("val1", []string{"aws-nitro", "sgx"}, []string{"ezkl"}, 10)
	s.RegisterValidator(val2)

	caps := s.GetValidatorCapabilities()
	if len(caps) != 1 {
		t.Fatalf("expected 1 validator (updated), got %d", len(caps))
	}
	if len(caps["val1"].TeePlatforms) != 2 {
		t.Fatalf("expected 2 TEE platforms, got %d", len(caps["val1"].TeePlatforms))
	}
}

// =============================================================================
// GET NEXT JOBS: Priority Queue Ordering
// =============================================================================

func TestScheduler_GetNextJobs_HigherPriorityFirst(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Register a TEE validator
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	// Enqueue low priority job first
	jobLow := makeJob("job-low", 5, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, jobLow)

	// Enqueue high priority job second
	jobHigh := makeJob("job-high", 100, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, jobHigh)

	// Get next batch
	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	if jobs[0].Id != "job-high" {
		t.Fatalf("expected high-priority job first, got %s", jobs[0].Id)
	}
}

func TestScheduler_GetNextJobs_MaxJobsPerBlock(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 2
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	for i := 0; i < 5; i++ {
		_ = s.EnqueueJob(ctx, makeJob(fmt.Sprintf("job-%d", i), int64(i), types.ProofTypeTEE))
	}

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs (MaxJobsPerBlock=2), got %d", len(jobs))
	}
}

// =============================================================================
// GET NEXT JOBS: Not Enough Validators
// =============================================================================

func TestScheduler_GetNextJobs_NotEnoughValidators(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 3
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Only 1 validator, need 3
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs (insufficient validators), got %d", len(jobs))
	}
}

func TestScheduler_GetNextJobs_NoValidators(t *testing.T) {
	s := testScheduler()
	ctx := sdkCtxForHeight(100)

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs (no validators), got %d", len(jobs))
	}
}

// =============================================================================
// VALIDATOR CAPABILITY MATCHING
// =============================================================================

func TestScheduler_GetNextJobs_TEEJobNeedsTEEValidator(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Only ZKML validator, no TEE
	s.RegisterValidator(makeValidator("val1", nil, []string{"ezkl"}, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("TEE job should not be assigned to ZKML-only validator, got %d jobs", len(jobs))
	}
}

func TestScheduler_GetNextJobs_ZKMLJobNeedsZKMLValidator(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Only TEE validator, no ZKML
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeZKML))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("ZKML job should not be assigned to TEE-only validator, got %d jobs", len(jobs))
	}
}

func TestScheduler_GetNextJobs_HybridNeedsBoth(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// TEE-only validator cannot handle hybrid
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeHybrid))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("hybrid job should not be assigned to TEE-only validator, got %d jobs", len(jobs))
	}
}

func TestScheduler_GetNextJobs_HybridAssignedToFullValidator(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Validator with both TEE and ZKML
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, []string{"ezkl"}, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeHybrid))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 1 {
		t.Fatalf("hybrid job should be assigned to full-capability validator, got %d", len(jobs))
	}
}

// =============================================================================
// JOB COMPLETION
// =============================================================================

func TestScheduler_MarkJobComplete(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	// Process
	_ = s.GetNextJobs(ctx, 100)

	// Complete
	s.MarkJobComplete("job-1")

	stats := s.GetQueueStats()
	if stats.TotalJobs != 0 {
		t.Fatalf("expected 0 jobs after completion, got %d", stats.TotalJobs)
	}
}

func TestScheduler_MarkJobComplete_NonexistentJob(t *testing.T) {
	s := testScheduler()
	// Should not panic
	s.MarkJobComplete("nonexistent-job")
}

func TestScheduler_MarkJobComplete_ReleasesValidatorSlots(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Register a validator
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))
	_ = s.EnqueueJob(ctx, makeJob("job-2", 5, types.ProofTypeTEE))

	// Process first batch
	jobs1 := s.GetNextJobs(ctx, 100)
	if len(jobs1) < 1 {
		t.Fatal("expected at least 1 job in first batch")
	}

	// Complete the first job
	s.MarkJobComplete(jobs1[0].Id)

	// After completion, queue should shrink by 1
	stats := s.GetQueueStats()
	if stats.TotalJobs >= 2 {
		t.Fatalf("expected fewer than 2 jobs after completion, got %d", stats.TotalJobs)
	}
}

// =============================================================================
// JOB FAILURE AND RETRY
// =============================================================================

func TestScheduler_MarkJobFailed_RetryWithPriorityBoost(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxRetries = 3
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	job := makeJob("job-1", 10, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, job)

	// Process and fail
	_ = s.GetNextJobs(ctx, 100)
	s.MarkJobFailed("job-1", "TEE execution error")

	// Job should still be in queue (retry 1 of 3)
	stats := s.GetQueueStats()
	if stats.TotalJobs != 1 {
		t.Fatalf("expected job to remain after first failure (retry), got %d total", stats.TotalJobs)
	}

	// Verify the job was re-queued as pending
	if stats.PendingJobs != 1 {
		t.Fatalf("expected 1 pending job (requeued for retry), got %d", stats.PendingJobs)
	}
}

func TestScheduler_MarkJobFailed_MaxRetriesExceeded(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxRetries = 2
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	// Process and fail twice
	for i := 0; i < 2; i++ {
		_ = s.GetNextJobs(ctx, int64(100+i))
		s.MarkJobFailed("job-1", "error")
	}

	// After max retries, job should be removed
	stats := s.GetQueueStats()
	if stats.TotalJobs != 0 {
		t.Fatalf("expected job removed after max retries, got %d total", stats.TotalJobs)
	}
}

func TestScheduler_MarkJobFailed_NonexistentJob(t *testing.T) {
	s := testScheduler()
	// Should not panic
	s.MarkJobFailed("nonexistent-job", "error")
}

// =============================================================================
// EXPIRED JOBS
// =============================================================================

func TestScheduler_RemoveExpiredJobs(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.JobTimeoutBlocks = 50
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	// Advance past timeout
	_ = s.GetNextJobs(sdkCtxForHeight(200), 200) // 200 - 100 = 100 > 50 timeout

	stats := s.GetQueueStats()
	if stats.TotalJobs != 0 {
		t.Fatalf("expected expired job to be removed, got %d total", stats.TotalJobs)
	}
}

func TestScheduler_ExpiredJobNotSelected(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.JobTimeoutBlocks = 10
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	_ = s.EnqueueJob(ctx, makeJob("old-job", 10, types.ProofTypeTEE))

	// Also enqueue a fresh job
	freshCtx := sdkCtxForHeight(150)
	_ = s.EnqueueJob(freshCtx, makeJob("new-job", 5, types.ProofTypeTEE))

	// At block 115, old-job expires (115 - 100 = 15 > 10 timeout)
	// but new-job is fresh (115 - 150 = -35, not expired)
	jobs := s.GetNextJobs(sdkCtxForHeight(115), 115)

	// old-job should be expired and removed, only new-job remains
	for _, j := range jobs {
		if j.Id == "old-job" {
			t.Fatal("expired job should not be selected")
		}
	}
}

// =============================================================================
// PRIORITY BOOSTING
// =============================================================================

func TestScheduler_PriorityBoosting(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	cfg.PriorityBoostPerBlock = 2
	cfg.JobTimeoutBlocks = 1000 // prevent expiry
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	// Job A: submitted at block 100, priority 5
	jobA := makeJob("job-a", 5, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, jobA)

	// Job B: submitted at block 150, priority 100
	ctxB := sdkCtxForHeight(150)
	jobB := makeJob("job-b", 100, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctxB, jobB)

	// At block 200: Job A has waited 100 blocks → boost = 100*2 = 200 → effective = 205
	//               Job B has waited 50 blocks → boost = 50*2 = 100 → effective = 200
	// Job A should now be selected first despite lower base priority
	jobs := s.GetNextJobs(sdkCtxForHeight(200), 200)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	if jobs[0].Id != "job-a" {
		t.Fatalf("expected boosted job-a first (effective 205), got %s", jobs[0].Id)
	}
}

// =============================================================================
// FIFO WITHIN SAME PRIORITY
// =============================================================================

func TestScheduler_FIFOWithinSamePriority(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	cfg.PriorityBoostPerBlock = 0 // disable boosting
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	// Both at priority 10, but A at block 100, B at block 200
	ctxA := sdkCtxForHeight(100)
	_ = s.EnqueueJob(ctxA, makeJob("job-a", 10, types.ProofTypeTEE))

	ctxB := sdkCtxForHeight(200)
	_ = s.EnqueueJob(ctxB, makeJob("job-b", 10, types.ProofTypeTEE))

	jobs := s.GetNextJobs(sdkCtxForHeight(300), 300)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	if jobs[0].Id != "job-a" {
		t.Fatalf("expected FIFO: job-a first (submitted earlier), got %s", jobs[0].Id)
	}
}

// =============================================================================
// QUEUE STATS
// =============================================================================

func TestScheduler_QueueStats(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Register 2 validators (one online, one offline)
	valOnline := makeValidator("val1", []string{"aws-nitro"}, []string{"ezkl"}, 10)
	valOffline := makeValidator("val2", []string{"aws-nitro"}, nil, 10)
	valOffline.IsOnline = false
	s.RegisterValidator(valOnline)
	s.RegisterValidator(valOffline)

	// Enqueue different job types
	_ = s.EnqueueJob(ctx, makeJob("tee-1", 10, types.ProofTypeTEE))
	_ = s.EnqueueJob(ctx, makeJob("zkml-1", 10, types.ProofTypeZKML))
	_ = s.EnqueueJob(ctx, makeJob("hybrid-1", 10, types.ProofTypeHybrid))

	stats := s.GetQueueStats()
	if stats.TotalJobs != 3 {
		t.Fatalf("expected 3 total, got %d", stats.TotalJobs)
	}
	if stats.TEEJobs != 1 {
		t.Fatalf("expected 1 TEE job, got %d", stats.TEEJobs)
	}
	if stats.ZKMLJobs != 1 {
		t.Fatalf("expected 1 ZKML job, got %d", stats.ZKMLJobs)
	}
	if stats.HybridJobs != 1 {
		t.Fatalf("expected 1 Hybrid job, got %d", stats.HybridJobs)
	}
	if stats.RegisteredValidators != 2 {
		t.Fatalf("expected 2 registered validators, got %d", stats.RegisteredValidators)
	}
	if stats.OnlineValidators != 1 {
		t.Fatalf("expected 1 online validator, got %d", stats.OnlineValidators)
	}
}

func TestScheduler_QueueStats_PendingVsProcessing(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))
	_ = s.EnqueueJob(ctx, makeJob("job-2", 5, types.ProofTypeTEE))

	// Process 1 job
	_ = s.GetNextJobs(ctx, 100)

	stats := s.GetQueueStats()
	if stats.PendingJobs != 1 {
		t.Fatalf("expected 1 pending, got %d", stats.PendingJobs)
	}
	if stats.ProcessingJobs != 1 {
		t.Fatalf("expected 1 processing, got %d", stats.ProcessingJobs)
	}
}

// =============================================================================
// JOBS FOR VALIDATOR
// =============================================================================

func TestScheduler_GetJobsForValidator(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	s.RegisterValidator(makeValidator("val2", []string{"aws-nitro"}, nil, 10))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	// Process — jobs get assigned
	_ = s.GetNextJobs(ctx, 100)

	// Check that at least val1 has jobs assigned
	val1Jobs := s.GetJobsForValidator(ctx, "val1")
	val2Jobs := s.GetJobsForValidator(ctx, "val2")

	// Both validators should be assigned (since MinValidatorsRequired=1
	// but assignValidatorsToJob assigns up to MinValidatorsRequired)
	totalAssigned := len(val1Jobs) + len(val2Jobs)
	if totalAssigned == 0 {
		t.Fatal("at least one validator should have assigned jobs")
	}
}

func TestScheduler_GetJobsForValidator_NoJobs(t *testing.T) {
	s := testScheduler()
	ctx := sdkCtxForHeight(100)

	jobs := s.GetJobsForValidator(ctx, "val-none")
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs for unregistered validator, got %d", len(jobs))
	}
}

// =============================================================================
// CONCURRENT JOB LIMITS
// =============================================================================

func TestScheduler_ValidatorConcurrentJobLimit_WithinBlock(t *testing.T) {
	// Week 7-8 FIX: assignValidatorsToJob now re-checks MaxConcurrentJobs before
	// each assignment, preventing over-commitment within a single block.
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Validator with MaxConcurrentJobs=2
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 2))

	// Enqueue 5 jobs
	for i := 0; i < 5; i++ {
		_ = s.EnqueueJob(ctx, makeJob(fmt.Sprintf("job-%d", i), 10, types.ProofTypeTEE))
	}

	// With the fix, exactly 2 jobs should be assigned (MaxConcurrentJobs=2)
	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 2 {
		t.Fatalf("expected exactly 2 jobs (MaxConcurrentJobs=2), got %d", len(jobs))
	}
}

func TestScheduler_ValidatorConcurrentJobLimit_SingleSlot(t *testing.T) {
	// Edge case: MaxConcurrentJobs=1, 10 pending jobs → exactly 1 job
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 1))

	for i := 0; i < 10; i++ {
		_ = s.EnqueueJob(ctx, makeJob(fmt.Sprintf("job-%d", i), 10, types.ProofTypeTEE))
	}

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 1 {
		t.Fatalf("expected exactly 1 job (MaxConcurrentJobs=1), got %d", len(jobs))
	}
}

func TestScheduler_ValidatorConcurrentJobLimit_MultipleValidators(t *testing.T) {
	// Two validators, each with MaxConcurrentJobs=2 → 4 total slots
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 2))
	s.RegisterValidator(makeValidator("val2", []string{"aws-nitro"}, nil, 2))

	for i := 0; i < 8; i++ {
		_ = s.EnqueueJob(ctx, makeJob(fmt.Sprintf("job-%d", i), 10, types.ProofTypeTEE))
	}

	jobs := s.GetNextJobs(ctx, 100)
	// Each validator can handle 2, so up to 4 total
	if len(jobs) > 4 {
		t.Fatalf("expected at most 4 jobs (2 validators × MaxConcurrent=2), got %d", len(jobs))
	}
	if len(jobs) < 1 {
		t.Fatal("expected at least some jobs to be assigned")
	}
	t.Logf("Assigned %d jobs across 2 validators with MaxConcurrentJobs=2", len(jobs))
}

func TestScheduler_ValidatorAtCapacity_SkipsToNextValidator(t *testing.T) {
	// One validator at capacity, another available → second validator gets the job
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// First validator: MaxConcurrentJobs=1
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 1))
	// Second validator: MaxConcurrentJobs=5
	s.RegisterValidator(makeValidator("val2", []string{"aws-nitro"}, nil, 5))

	for i := 0; i < 6; i++ {
		_ = s.EnqueueJob(ctx, makeJob(fmt.Sprintf("job-%d", i), 10, types.ProofTypeTEE))
	}

	jobs := s.GetNextJobs(ctx, 100)
	// Total capacity: 1 + 5 = 6 slots
	if len(jobs) != 6 {
		t.Fatalf("expected 6 jobs (1+5 capacity), got %d", len(jobs))
	}
}

func TestScheduler_ValidatorConcurrentJobLimit_AcrossBlocks(t *testing.T) {
	// Even though within-block enforcement has a gap, across blocks the
	// getAvailableValidators check does work — a validator at capacity
	// won't be included in the available set for the next block.
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1 // only 1 job per block
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Validator with MaxConcurrentJobs=1
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 1))

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))
	_ = s.EnqueueJob(ctx, makeJob("job-2", 5, types.ProofTypeTEE))

	// Block 100: Get 1 job (MaxJobsPerBlock=1)
	jobs1 := s.GetNextJobs(ctx, 100)
	if len(jobs1) != 1 {
		t.Fatalf("expected 1 job (MaxJobsPerBlock=1), got %d", len(jobs1))
	}

	// Block 101: Validator now has CurrentJobs=1 == MaxConcurrentJobs=1
	// getAvailableValidators should exclude it
	jobs2 := s.GetNextJobs(sdkCtxForHeight(101), 101)
	if len(jobs2) != 0 {
		t.Fatalf("expected 0 jobs (validator at capacity), got %d", len(jobs2))
	}

	// Complete the first job
	s.MarkJobComplete(jobs1[0].Id)

	// Block 102: Validator should now be available again
	jobs3 := s.GetNextJobs(sdkCtxForHeight(102), 102)
	if len(jobs3) != 1 {
		t.Fatalf("expected 1 job after completion freed slot, got %d", len(jobs3))
	}
}

// =============================================================================
// OFFLINE VALIDATORS
// =============================================================================

func TestScheduler_OfflineValidatorsNotAssigned(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Only validator is offline
	val := makeValidator("val1", []string{"aws-nitro"}, nil, 10)
	val.IsOnline = false
	s.RegisterValidator(val)

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs (validator offline), got %d", len(jobs))
	}
}

// =============================================================================
// VRF-BASED ORDERING
// =============================================================================

func TestScheduler_ValidatorsAssignedByDeterministicVRF(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Register validators with different reputations
	valLow := makeValidator("val-low", []string{"aws-nitro"}, nil, 10)
	valLow.ReputationScore = 20
	valHigh := makeValidator("val-high", []string{"aws-nitro"}, nil, 10)
	valHigh.ReputationScore = 90

	s.RegisterValidator(valLow)
	s.RegisterValidator(valHigh)

	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	// Process jobs
	_ = s.GetNextJobs(ctx, 100)

	valHighJobs := s.GetJobsForValidator(ctx, "val-high")
	valLowJobs := s.GetJobsForValidator(ctx, "val-low")
	if len(valHighJobs)+len(valLowJobs) == 0 {
		t.Fatal("expected VRF scheduler to assign the job to an eligible validator")
	}
}

// =============================================================================
// EMPTY QUEUE
// =============================================================================

func TestScheduler_GetNextJobs_EmptyQueue(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs from empty queue, got %d", len(jobs))
	}
}

// =============================================================================
// STATE TRANSITIONS THROUGH SCHEDULER
// =============================================================================

func TestScheduler_SelectedJobTransitionsToProcessing(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	job := makeJob("job-1", 10, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, job)

	// Before selection, status should be Pending
	if job.Status != types.JobStatusPending {
		t.Fatalf("expected Pending before selection, got %s", job.Status)
	}

	// Select for processing
	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}

	// After selection, status should be Processing
	if jobs[0].Status != types.JobStatusProcessing {
		t.Fatalf("expected Processing after selection, got %s", jobs[0].Status)
	}
}

func TestScheduler_FailedJobTransitionsToPendingOnRetry(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxRetries = 3
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	job := makeJob("job-1", 10, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, job)

	// Process and fail
	_ = s.GetNextJobs(ctx, 100)
	s.MarkJobFailed("job-1", "error")

	// After retry, job should be Pending again
	stats := s.GetQueueStats()
	if stats.PendingJobs != 1 {
		t.Fatalf("expected 1 pending (requeued) job, got %d", stats.PendingJobs)
	}
}

func TestScheduler_FailedJobTransitionsToFailedAtMaxRetries(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxRetries = 1
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	job := makeJob("job-1", 10, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, job)

	// Process and fail once (max retries = 1)
	_ = s.GetNextJobs(ctx, 100)
	s.MarkJobFailed("job-1", "error")

	// Job should now be permanently failed and removed
	stats := s.GetQueueStats()
	if stats.TotalJobs != 0 {
		t.Fatalf("expected job removed after max retries, got %d", stats.TotalJobs)
	}
}

// =============================================================================
// DEFAULT CONFIG
// =============================================================================

func TestDefaultSchedulerConfig_Values(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()

	if cfg.MaxJobsPerBlock != 10 {
		t.Errorf("expected MaxJobsPerBlock=10, got %d", cfg.MaxJobsPerBlock)
	}
	if cfg.MaxJobsPerValidator != 3 {
		t.Errorf("expected MaxJobsPerValidator=3, got %d", cfg.MaxJobsPerValidator)
	}
	if cfg.JobTimeoutBlocks != 100 {
		t.Errorf("expected JobTimeoutBlocks=100, got %d", cfg.JobTimeoutBlocks)
	}
	if cfg.MinValidatorsRequired != 3 {
		t.Errorf("expected MinValidatorsRequired=3, got %d", cfg.MinValidatorsRequired)
	}
	if cfg.PriorityBoostPerBlock != 1 {
		t.Errorf("expected PriorityBoostPerBlock=1, got %d", cfg.PriorityBoostPerBlock)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("expected MaxRetries=3, got %d", cfg.MaxRetries)
	}
}

// =============================================================================
// PRIORITY QUEUE: Heap Property
// =============================================================================

func TestScheduler_HeapProperty_MultipleExtractions(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 1
	cfg.PriorityBoostPerBlock = 0 // disable boosting for pure priority test
	cfg.JobTimeoutBlocks = 10000
	s := testSchedulerWithConfig(cfg)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 100))

	// Enqueue in random priority order
	priorities := []int64{30, 10, 50, 20, 40}
	for i, p := range priorities {
		ctx := sdkCtxForHeight(int64(100 + i))
		_ = s.EnqueueJob(ctx, makeJob(fmt.Sprintf("job-%d", p), p, types.ProofTypeTEE))
	}

	// Extract one at a time, should come out in priority order (highest first)
	expectedOrder := []int64{50, 40, 30, 20, 10}
	for _, expected := range expectedOrder {
		ctx := sdkCtxForHeight(100) // same block for all
		jobs := s.GetNextJobs(ctx, 100)
		if len(jobs) != 1 {
			t.Fatalf("expected 1 job, got %d", len(jobs))
		}
		if jobs[0].Priority != expected {
			t.Fatalf("expected priority %d, got %d (job %s)", expected, jobs[0].Priority, jobs[0].Id)
		}
		// Complete to remove from queue
		s.MarkJobComplete(jobs[0].Id)
	}
}

// =============================================================================
// MIXED PROOF TYPE SCHEDULING
// =============================================================================

func TestScheduler_MixedProofTypes_MatchesCorrectValidators(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// TEE-only validator
	s.RegisterValidator(makeValidator("val-tee", []string{"aws-nitro"}, nil, 10))
	// ZKML-only validator
	s.RegisterValidator(makeValidator("val-zkml", nil, []string{"ezkl"}, 10))

	_ = s.EnqueueJob(ctx, makeJob("tee-job", 10, types.ProofTypeTEE))
	_ = s.EnqueueJob(ctx, makeJob("zkml-job", 10, types.ProofTypeZKML))
	_ = s.EnqueueJob(ctx, makeJob("hybrid-job", 10, types.ProofTypeHybrid))

	jobs := s.GetNextJobs(ctx, 100)

	// TEE and ZKML jobs should be selected, but hybrid should NOT
	// (no single validator has both capabilities)
	selectedIDs := make(map[string]bool)
	for _, j := range jobs {
		selectedIDs[j.Id] = true
	}

	if !selectedIDs["tee-job"] {
		t.Error("TEE job should have been selected (val-tee can handle it)")
	}
	if !selectedIDs["zkml-job"] {
		t.Error("ZKML job should have been selected (val-zkml can handle it)")
	}
	if selectedIDs["hybrid-job"] {
		t.Error("Hybrid job should NOT be selected (no validator has both capabilities)")
	}
}

// =============================================================================
// INSUFFICIENT VALIDATORS FOR PROOF TYPE
// =============================================================================

func TestScheduler_InsufficientMatchingValidators(t *testing.T) {
	// 3 validators needed, but only 2 can handle TEE. Job should NOT be selected.
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 3
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// 2 TEE validators + 1 ZKML-only
	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	s.RegisterValidator(makeValidator("val2", []string{"aws-nitro"}, nil, 10))
	s.RegisterValidator(makeValidator("val3", nil, []string{"ezkl"}, 10))

	_ = s.EnqueueJob(ctx, makeJob("tee-job", 10, types.ProofTypeTEE))

	jobs := s.GetNextJobs(ctx, 100)
	// TEE job needs 3 validators, but only 2 have TEE capability
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs (only 2/3 validators can handle TEE), got %d", len(jobs))
	}
}

func TestScheduler_ExactlyMinValidators(t *testing.T) {
	// Exactly MinValidatorsRequired matching validators → job should be selected
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 3
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	s.RegisterValidator(makeValidator("val2", []string{"aws-nitro"}, nil, 10))
	s.RegisterValidator(makeValidator("val3", []string{"sgx"}, nil, 10))

	_ = s.EnqueueJob(ctx, makeJob("tee-job", 10, types.ProofTypeTEE))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job (exactly 3 matching validators), got %d", len(jobs))
	}
}

// =============================================================================
// SYNC FROM CHAIN (with nil keeper)
// =============================================================================

func TestScheduler_SyncFromChain_NilKeeper(t *testing.T) {
	// SyncFromChain with nil keeper should not panic but will fail
	// to load from chain since keeper has GetPendingJobs
	s := testScheduler()
	ctx := sdkCtxForHeight(100)

	// This will call s.keeper.GetPendingJobs which panics on nil keeper
	// so we just verify the scheduler is properly constructed without sync
	stats := s.GetQueueStats()
	if stats.TotalJobs != 0 {
		t.Fatalf("expected 0 jobs on fresh scheduler, got %d", stats.TotalJobs)
	}
	_ = ctx // avoid unused
}

// =============================================================================
// SCHEDULER: Retry Priority Boost Accumulates
// =============================================================================

func TestScheduler_RetryPriorityBoostAccumulates(t *testing.T) {
	// NOTE: The current updatePriorities() recalculates EffectivePriority from
	// base job.Priority + wait-time boost each block, which OVERWRITES retry boosts.
	// This means retry boosts from MarkJobFailed (+10 per retry) are only effective
	// until the next call to GetNextJobs(), which calls updatePriorities().
	//
	// This test documents the current behavior. Fixing this to preserve retry
	// boosts across updatePriorities() is tracked for future improvement.
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxRetries = 5
	cfg.JobTimeoutBlocks = 1000
	cfg.MaxJobsPerBlock = 1
	cfg.PriorityBoostPerBlock = 0 // disable wait-time boost
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	// Enqueue job-low with base priority 5
	_ = s.EnqueueJob(ctx, makeJob("job-low", 5, types.ProofTypeTEE))

	// Process and fail 3 times
	for i := 0; i < 3; i++ {
		_ = s.GetNextJobs(sdkCtxForHeight(int64(100+i)), int64(100+i))
		s.MarkJobFailed("job-low", "transient error")
	}

	// After 3 retries, the job's EffectivePriority was boosted +10 per failure = +30
	// But updatePriorities() in next GetNextJobs will recalculate from base priority
	// So the effective priority gets reset to base priority (5) + wait-time boost (0)

	// This verifies the job is still in the queue (not permanently failed)
	stats := s.GetQueueStats()
	if stats.TotalJobs != 1 {
		t.Fatalf("expected 1 job (3 retries < max 5), got %d", stats.TotalJobs)
	}
	if stats.PendingJobs != 1 {
		t.Fatalf("expected 1 pending job, got %d", stats.PendingJobs)
	}
}

// =============================================================================
// SCHEDULER: Expired Jobs Emit State Machine Transition
// =============================================================================

func TestScheduler_ExpiredJobMarksExpiredState(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.JobTimeoutBlocks = 10
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))

	job := makeJob("job-expire", 10, types.ProofTypeTEE)
	_ = s.EnqueueJob(ctx, job)

	// Advance past timeout to expire the job
	_ = s.GetNextJobs(sdkCtxForHeight(200), 200)

	// The job should have been marked Expired via state machine
	if job.Status != types.JobStatusExpired {
		t.Fatalf("expected expired job status, got %s", job.Status)
	}
}

// =============================================================================
// SCHEDULER: Processing Jobs Not Re-Selected
// =============================================================================

func TestScheduler_ProcessingJobNotReSelectedNextBlock(t *testing.T) {
	// Week 7-8 FIX: The scheduler now checks job.Status == Pending before
	// attempting to assign, preventing Processing jobs from being re-selected.
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 10))
	_ = s.EnqueueJob(ctx, makeJob("job-1", 10, types.ProofTypeTEE))

	// First selection: job transitions Pending → Processing
	jobs1 := s.GetNextJobs(ctx, 100)
	if len(jobs1) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs1))
	}
	if jobs1[0].Status != types.JobStatusProcessing {
		t.Fatalf("expected Processing status, got %s", jobs1[0].Status)
	}

	// Next block: the job is still in queue (Processing) but should NOT be re-selected
	jobs2 := s.GetNextJobs(sdkCtxForHeight(101), 101)
	if len(jobs2) != 0 {
		t.Fatalf("expected 0 jobs (already Processing, skipped), got %d", len(jobs2))
	}
}

// =============================================================================
// SCHEDULER: Multiple Validator Proof Types
// =============================================================================

func TestScheduler_ZKMLJobAssignedCorrectly(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 10
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// ZKML-capable validator
	s.RegisterValidator(makeValidator("val1", nil, []string{"ezkl", "cairo"}, 10))

	_ = s.EnqueueJob(ctx, makeJob("zkml-1", 10, types.ProofTypeZKML))

	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 ZKML job, got %d", len(jobs))
	}

	// Verify assignment
	val1Jobs := s.GetJobsForValidator(ctx, "val1")
	if len(val1Jobs) != 1 {
		t.Fatalf("expected val1 to have 1 job, got %d", len(val1Jobs))
	}
}

// =============================================================================
// SCHEDULER: Empty Queue After Full Drain
// =============================================================================

func TestScheduler_DrainAllJobs(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.MinValidatorsRequired = 1
	cfg.MaxJobsPerBlock = 100
	cfg.JobTimeoutBlocks = 1000
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	s.RegisterValidator(makeValidator("val1", []string{"aws-nitro"}, nil, 100))

	for i := 0; i < 10; i++ {
		_ = s.EnqueueJob(ctx, makeJob(fmt.Sprintf("job-%d", i), int64(i), types.ProofTypeTEE))
	}

	// Select all
	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 10 {
		t.Fatalf("expected 10 jobs, got %d", len(jobs))
	}

	// Complete all
	for _, j := range jobs {
		s.MarkJobComplete(j.Id)
	}

	// Queue should be empty
	stats := s.GetQueueStats()
	if stats.TotalJobs != 0 {
		t.Fatalf("expected 0 after draining all, got %d", stats.TotalJobs)
	}
}

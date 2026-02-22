package types_test

import (
	"crypto/sha256"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// HELPERS
// =============================================================================

// testRequester returns a valid bech32 cosmos address for testing.
func testRequester() string {
	return sdk.AccAddress(make([]byte, 20)).String()
}

func makeTestJob(status types.JobStatus) *types.ComputeJob {
	modelHash := sha256.Sum256([]byte("test-model"))
	inputHash := sha256.Sum256([]byte("test-input"))

	fee := sdk.NewInt64Coin("uaeth", 1000)
	blockTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	job := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		testRequester(),
		types.ProofTypeTEE,
		"credit_scoring",
		fee,
		100,       // blockHeight
		blockTime, // deterministic block time
	)
	// Force the desired status for testing transitions.
	job.Status = status
	return job
}

func makeTestJobAtHeight(height int64) *types.ComputeJob {
	modelHash := sha256.Sum256([]byte("test-model"))
	inputHash := sha256.Sum256([]byte("test-input"))

	fee := sdk.NewInt64Coin("uaeth", 1000)
	blockTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	return types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		testRequester(),
		types.ProofTypeTEE,
		"credit_scoring",
		fee,
		height,
		blockTime,
	)
}

// =============================================================================
// STATE MACHINE: Valid Transitions
// =============================================================================

func TestStateMachine_Pending_To_Processing(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	if err := job.MarkProcessing(); err != nil {
		t.Fatalf("expected Pending → Processing to succeed, got: %v", err)
	}
	if job.Status != types.JobStatusProcessing {
		t.Fatalf("expected status Processing, got %s", job.Status)
	}
}

func TestStateMachine_Pending_To_Expired(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	if err := job.MarkExpired(); err != nil {
		t.Fatalf("expected Pending → Expired to succeed, got: %v", err)
	}
	if job.Status != types.JobStatusExpired {
		t.Fatalf("expected status Expired, got %s", job.Status)
	}
}

func TestStateMachine_Pending_To_Failed(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	if err := job.MarkFailed(); err != nil {
		t.Fatalf("expected Pending → Failed to succeed, got: %v", err)
	}
	if job.Status != types.JobStatusFailed {
		t.Fatalf("expected status Failed, got %s", job.Status)
	}
}

func TestStateMachine_Processing_To_Completed(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	outputHash := sha256.Sum256([]byte("output"))
	if err := job.MarkCompleted(outputHash[:], "seal-123"); err != nil {
		t.Fatalf("expected Processing → Completed to succeed, got: %v", err)
	}
	if job.Status != types.JobStatusCompleted {
		t.Fatalf("expected status Completed, got %s", job.Status)
	}
	if job.SealId != "seal-123" {
		t.Fatalf("expected seal ID 'seal-123', got %s", job.SealId)
	}
	if len(job.OutputHash) == 0 {
		t.Fatal("expected output hash to be set")
	}
	if job.CompletedAt == nil {
		t.Fatal("expected CompletedAt to be set")
	}
}

func TestStateMachine_Processing_To_Failed(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	if err := job.MarkFailed(); err != nil {
		t.Fatalf("expected Processing → Failed to succeed, got: %v", err)
	}
	if job.Status != types.JobStatusFailed {
		t.Fatalf("expected status Failed, got %s", job.Status)
	}
}

func TestStateMachine_Processing_To_Pending_Retry(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	if err := job.RequeueForRetry(); err != nil {
		t.Fatalf("expected Processing → Pending (retry) to succeed, got: %v", err)
	}
	if job.Status != types.JobStatusPending {
		t.Fatalf("expected status Pending, got %s", job.Status)
	}
}

// =============================================================================
// STATE MACHINE: Invalid Transitions (Terminal States)
// =============================================================================

func TestStateMachine_Completed_Is_Terminal(t *testing.T) {
	job := makeTestJob(types.JobStatusCompleted)

	targets := []struct {
		name string
		fn   func() error
	}{
		{"Processing", job.MarkProcessing},
		{"Failed", job.MarkFailed},
		{"Expired", job.MarkExpired},
		{"Retry", job.RequeueForRetry},
	}
	for _, tc := range targets {
		err := tc.fn()
		if err == nil {
			t.Errorf("expected Completed → %s to fail, but it succeeded", tc.name)
		}
	}
}

func TestStateMachine_Failed_Is_Terminal(t *testing.T) {
	job := makeTestJob(types.JobStatusFailed)

	targets := []struct {
		name string
		fn   func() error
	}{
		{"Processing", job.MarkProcessing},
		{"Completed", func() error { return job.MarkCompleted(nil, "") }},
		{"Expired", job.MarkExpired},
		{"Retry", job.RequeueForRetry},
	}
	for _, tc := range targets {
		err := tc.fn()
		if err == nil {
			t.Errorf("expected Failed → %s to fail, but it succeeded", tc.name)
		}
	}
}

func TestStateMachine_Expired_Is_Terminal(t *testing.T) {
	job := makeTestJob(types.JobStatusExpired)

	targets := []struct {
		name string
		fn   func() error
	}{
		{"Processing", job.MarkProcessing},
		{"Failed", job.MarkFailed},
		{"Retry", job.RequeueForRetry},
	}
	for _, tc := range targets {
		err := tc.fn()
		if err == nil {
			t.Errorf("expected Expired → %s to fail, but it succeeded", tc.name)
		}
	}
}

// =============================================================================
// STATE MACHINE: Invalid Cross-Transitions
// =============================================================================

func TestStateMachine_Pending_Cannot_Complete(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	outputHash := sha256.Sum256([]byte("output"))
	err := job.MarkCompleted(outputHash[:], "seal-123")
	if err == nil {
		t.Fatal("expected Pending → Completed to fail (must go through Processing first)")
	}
	t.Logf("OK: correctly rejected Pending → Completed: %v", err)
}

func TestStateMachine_Pending_Cannot_Retry(t *testing.T) {
	// RequeueForRetry is Processing → Pending, not Pending → Pending
	job := makeTestJob(types.JobStatusPending)
	err := job.RequeueForRetry()
	if err == nil {
		t.Fatal("expected Pending → Pending (retry) to fail")
	}
}

func TestStateMachine_Processing_Cannot_Expire(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	err := job.MarkExpired()
	if err == nil {
		t.Fatal("expected Processing → Expired to fail")
	}
}

// =============================================================================
// STATE MACHINE: CanTransitionTo
// =============================================================================

func TestCanTransitionTo_AllValidTransitions(t *testing.T) {
	tests := []struct {
		from   types.JobStatus
		to     types.JobStatus
		expect bool
	}{
		// From Pending
		{types.JobStatusPending, types.JobStatusProcessing, true},
		{types.JobStatusPending, types.JobStatusExpired, true},
		{types.JobStatusPending, types.JobStatusFailed, true},
		{types.JobStatusPending, types.JobStatusCompleted, false},

		// From Processing
		{types.JobStatusProcessing, types.JobStatusCompleted, true},
		{types.JobStatusProcessing, types.JobStatusFailed, true},
		{types.JobStatusProcessing, types.JobStatusPending, true}, // retry
		{types.JobStatusProcessing, types.JobStatusExpired, false},

		// Terminal states
		{types.JobStatusCompleted, types.JobStatusPending, false},
		{types.JobStatusCompleted, types.JobStatusProcessing, false},
		{types.JobStatusCompleted, types.JobStatusFailed, false},
		{types.JobStatusCompleted, types.JobStatusExpired, false},

		{types.JobStatusFailed, types.JobStatusPending, false},
		{types.JobStatusFailed, types.JobStatusProcessing, false},
		{types.JobStatusFailed, types.JobStatusCompleted, false},
		{types.JobStatusFailed, types.JobStatusExpired, false},

		{types.JobStatusExpired, types.JobStatusPending, false},
		{types.JobStatusExpired, types.JobStatusProcessing, false},
		{types.JobStatusExpired, types.JobStatusCompleted, false},
		{types.JobStatusExpired, types.JobStatusFailed, false},
	}

	for _, tc := range tests {
		job := makeTestJob(tc.from)
		got := job.CanTransitionTo(tc.to)
		if got != tc.expect {
			t.Errorf("CanTransitionTo(%s → %s): got %v, want %v",
				tc.from, tc.to, got, tc.expect)
		}
	}
}

// =============================================================================
// STATE MACHINE: TransitionTo updates UpdatedAt
// =============================================================================

func TestStateMachine_TransitionTo_UpdatesTimestamp(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	originalUpdatedAt := job.UpdatedAt
	time.Sleep(1 * time.Millisecond) // ensure time advances

	if err := job.TransitionTo(types.JobStatusProcessing); err != nil {
		t.Fatal(err)
	}

	if job.UpdatedAt == nil {
		t.Fatal("UpdatedAt should be set after transition")
	}
	// UpdatedAt should have been updated
	if originalUpdatedAt != nil && job.UpdatedAt.AsTime().Before(originalUpdatedAt.AsTime()) {
		t.Error("UpdatedAt should not go backward")
	}
}

// =============================================================================
// DETERMINISTIC JOB CREATION
// =============================================================================

func TestNewComputeJobWithBlockTime_Deterministic(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model-A"))
	inputHash := sha256.Sum256([]byte("input-B"))
	fee := sdk.NewInt64Coin("uaeth", 500)
	blockTime := time.Date(2025, 6, 1, 10, 30, 0, 0, time.UTC)
	requester := testRequester()

	job1 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:], requester,
		types.ProofTypeTEE, "test", fee, 200, blockTime,
	)
	job2 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:], requester,
		types.ProofTypeTEE, "test", fee, 200, blockTime,
	)

	if job1.Id != job2.Id {
		t.Fatalf("same inputs should produce same ID: %s vs %s", job1.Id, job2.Id)
	}
}

func TestNewComputeJobWithBlockTime_DifferentHeight_DifferentID(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model-A"))
	inputHash := sha256.Sum256([]byte("input-B"))
	fee := sdk.NewInt64Coin("uaeth", 500)
	blockTime := time.Date(2025, 6, 1, 10, 30, 0, 0, time.UTC)
	requester := testRequester()

	job1 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:], requester,
		types.ProofTypeTEE, "test", fee, 200, blockTime,
	)
	job2 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:], requester,
		types.ProofTypeTEE, "test", fee, 201, blockTime,
	)

	if job1.Id == job2.Id {
		t.Fatal("different block heights should produce different IDs")
	}
}

func TestNewComputeJobWithBlockTime_DifferentTime_DifferentID(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model-A"))
	inputHash := sha256.Sum256([]byte("input-B"))
	fee := sdk.NewInt64Coin("uaeth", 500)
	blockTime1 := time.Date(2025, 6, 1, 10, 30, 0, 0, time.UTC)
	blockTime2 := time.Date(2025, 6, 1, 10, 30, 1, 0, time.UTC) // 1 second later
	requester := testRequester()

	job1 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:], requester,
		types.ProofTypeTEE, "test", fee, 200, blockTime1,
	)
	job2 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:], requester,
		types.ProofTypeTEE, "test", fee, 200, blockTime2,
	)

	if job1.Id == job2.Id {
		t.Fatal("different block times should produce different IDs")
	}
}

func TestNewComputeJobWithBlockTime_StatusIsPending(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	fee := sdk.NewInt64Coin("uaeth", 100)
	bt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	job := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		testRequester(),
		types.ProofTypeTEE, "test", fee, 1, bt,
	)

	if job.Status != types.JobStatusPending {
		t.Fatalf("new job should be Pending, got %s", job.Status)
	}
}

func TestNewComputeJobWithBlockTime_CreatedAtFromBlockTime(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	fee := sdk.NewInt64Coin("uaeth", 100)
	bt := time.Date(2025, 3, 15, 14, 0, 0, 0, time.UTC)

	job := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		testRequester(),
		types.ProofTypeTEE, "test", fee, 50, bt,
	)

	if job.CreatedAt == nil {
		t.Fatal("CreatedAt should not be nil")
	}
	if !job.CreatedAt.AsTime().Equal(bt) {
		t.Fatalf("CreatedAt should equal block time: got %v, want %v",
			job.CreatedAt.AsTime(), bt)
	}
}

func TestNewComputeJobWithBlockTime_ExpiresAt24Hours(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	fee := sdk.NewInt64Coin("uaeth", 100)
	bt := time.Date(2025, 3, 15, 14, 0, 0, 0, time.UTC)

	job := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		testRequester(),
		types.ProofTypeTEE, "test", fee, 50, bt,
	)

	expected := bt.Add(24 * time.Hour)
	if job.ExpiresAt == nil {
		t.Fatal("ExpiresAt should not be nil")
	}
	if !job.ExpiresAt.AsTime().Equal(expected) {
		t.Fatalf("ExpiresAt should be 24h after block time: got %v, want %v",
			job.ExpiresAt.AsTime(), expected)
	}
}

// =============================================================================
// EXPIRY: Block-Height-Based (Deterministic)
// =============================================================================

func TestIsExpiredAtHeight_NotExpired(t *testing.T) {
	job := makeTestJobAtHeight(100)
	// DefaultJobExpiryBlocks = 14400
	if job.IsExpiredAtHeight(100 + types.DefaultJobExpiryBlocks) {
		t.Fatal("job should NOT be expired at exactly the expiry boundary")
	}
}

func TestIsExpiredAtHeight_JustExpired(t *testing.T) {
	job := makeTestJobAtHeight(100)
	if !job.IsExpiredAtHeight(100 + types.DefaultJobExpiryBlocks + 1) {
		t.Fatal("job should be expired one block after expiry boundary")
	}
}

func TestIsExpiredAtHeight_WayPastExpiry(t *testing.T) {
	job := makeTestJobAtHeight(100)
	if !job.IsExpiredAtHeight(100 + types.DefaultJobExpiryBlocks + 10000) {
		t.Fatal("job should be expired well past expiry boundary")
	}
}

func TestIsExpiredAtHeight_SameBlock(t *testing.T) {
	job := makeTestJobAtHeight(100)
	if job.IsExpiredAtHeight(100) {
		t.Fatal("job should not be expired at the same block it was created")
	}
}

func TestIsExpiredAtHeight_ZeroHeight(t *testing.T) {
	job := makeTestJobAtHeight(0)
	if !job.IsExpiredAtHeight(types.DefaultJobExpiryBlocks + 1) {
		t.Fatal("job at height 0 should expire at DefaultJobExpiryBlocks+1")
	}
}

// =============================================================================
// EXPIRY: Time-Based (IsExpiredAt - Deterministic)
// =============================================================================

func TestIsExpiredAt_NotExpired(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	fee := sdk.NewInt64Coin("uaeth", 100)
	bt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	job := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		testRequester(),
		types.ProofTypeTEE, "test", fee, 1, bt,
	)

	// 12 hours later — not expired yet
	checkTime := bt.Add(12 * time.Hour)
	if job.IsExpiredAt(checkTime) {
		t.Fatal("job should not be expired at 12h")
	}
}

func TestIsExpiredAt_JustExpired(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	fee := sdk.NewInt64Coin("uaeth", 100)
	bt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	job := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		testRequester(),
		types.ProofTypeTEE, "test", fee, 1, bt,
	)

	// 24h + 1s later — expired
	checkTime := bt.Add(24*time.Hour + time.Second)
	if !job.IsExpiredAt(checkTime) {
		t.Fatal("job should be expired after 24h + 1s")
	}
}

func TestIsExpiredAt_NilExpiresAt(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	job.ExpiresAt = nil

	if job.IsExpiredAt(time.Now()) {
		t.Fatal("job with nil ExpiresAt should never be expired via time check")
	}
}

// =============================================================================
// GENERATE ID: Determinism
// =============================================================================

func TestGenerateID_DeterministicAcrossMultipleCalls(t *testing.T) {
	job := makeTestJobAtHeight(100)
	id1 := job.GenerateID()
	id2 := job.GenerateID()
	id3 := job.GenerateID()

	if id1 != id2 || id2 != id3 {
		t.Fatalf("GenerateID should be deterministic: %s, %s, %s", id1, id2, id3)
	}
}

func TestGenerateID_Length(t *testing.T) {
	job := makeTestJobAtHeight(100)
	id := job.GenerateID()
	if len(id) != 16 {
		t.Fatalf("expected ID length 16 hex chars, got %d: %s", len(id), id)
	}
}

func TestGenerateID_DifferentRequesters(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	fee := sdk.NewInt64Coin("uaeth", 100)
	bt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	addrA := sdk.AccAddress([]byte("requester-addr-aaa1")).String()
	addrB := sdk.AccAddress([]byte("requester-addr-bbb2")).String()

	job1 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		addrA,
		types.ProofTypeTEE, "test", fee, 100, bt,
	)
	job2 := types.NewComputeJobWithBlockTime(
		modelHash[:], inputHash[:],
		addrB,
		types.ProofTypeTEE, "test", fee, 100, bt,
	)

	if job1.Id == job2.Id {
		t.Fatal("different requesters should produce different IDs")
	}
}

// =============================================================================
// VERIFICATION RESULTS: Deterministic AddVerificationResultAt
// =============================================================================

func TestAddVerificationResultAt_DeterministicTimestamp(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	bt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	result := types.VerificationResult{
		ValidatorAddress: "val1",
		Success:          true,
		OutputHash:       make([]byte, 32),
	}

	job.AddVerificationResultAt(result, bt)

	if len(job.VerificationResults) != 1 {
		t.Fatalf("expected 1 result, got %d", len(job.VerificationResults))
	}
	if !job.UpdatedAt.AsTime().Equal(bt) {
		t.Fatalf("UpdatedAt should equal block time: got %v, want %v",
			job.UpdatedAt.AsTime(), bt)
	}
}

// =============================================================================
// CONSENSUS OUTPUT
// =============================================================================

func TestGetConsensusOutput_NoResults(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	_, ok := job.GetConsensusOutput(3)
	if ok {
		t.Fatal("should not have consensus with no results")
	}
}

func TestGetConsensusOutput_InsufficientVotes(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	outputHash := sha256.Sum256([]byte("output"))
	job.AddVerificationResult(types.VerificationResult{
		ValidatorAddress: "val1",
		Success:          true,
		OutputHash:       outputHash[:],
	})

	_, ok := job.GetConsensusOutput(3)
	if ok {
		t.Fatal("should not have consensus with only 1 vote (need 3)")
	}
}

func TestGetConsensusOutput_ConsensusReached(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	outputHash := sha256.Sum256([]byte("output"))
	for i := 0; i < 3; i++ {
		job.AddVerificationResult(types.VerificationResult{
			ValidatorAddress: "val" + string(rune('1'+i)),
			Success:          true,
			OutputHash:       outputHash[:],
		})
	}

	output, ok := job.GetConsensusOutput(3)
	if !ok {
		t.Fatal("should have consensus with 3 matching votes")
	}
	if len(output) == 0 {
		t.Fatal("consensus output should not be empty")
	}
}

func TestGetConsensusOutput_Disagreement(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	output1 := sha256.Sum256([]byte("output1"))
	output2 := sha256.Sum256([]byte("output2"))

	job.AddVerificationResult(types.VerificationResult{
		ValidatorAddress: "val1", Success: true, OutputHash: output1[:],
	})
	job.AddVerificationResult(types.VerificationResult{
		ValidatorAddress: "val2", Success: true, OutputHash: output2[:],
	})
	job.AddVerificationResult(types.VerificationResult{
		ValidatorAddress: "val3", Success: true, OutputHash: output1[:],
	})

	_, ok := job.GetConsensusOutput(3)
	if ok {
		t.Fatal("should not reach consensus with split votes (2 vs 1)")
	}
}

func TestGetConsensusOutput_SkipsFailures(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	outputHash := sha256.Sum256([]byte("output"))

	job.AddVerificationResult(types.VerificationResult{
		ValidatorAddress: "val1", Success: true, OutputHash: outputHash[:],
	})
	job.AddVerificationResult(types.VerificationResult{
		ValidatorAddress: "val2", Success: false, OutputHash: nil,
	})
	job.AddVerificationResult(types.VerificationResult{
		ValidatorAddress: "val3", Success: true, OutputHash: outputHash[:],
	})

	_, ok := job.GetConsensusOutput(3)
	if ok {
		t.Fatal("should not reach consensus — only 2 successful votes, need 3")
	}
}

func TestGetConsensusOutput_NilResult(t *testing.T) {
	job := makeTestJob(types.JobStatusProcessing)
	job.VerificationResults = append(job.VerificationResults, nil)
	_, ok := job.GetConsensusOutput(1)
	if ok {
		t.Fatal("nil results should be skipped, not counted")
	}
}

// =============================================================================
// VALIDATION
// =============================================================================

func TestValidate_ValidJob(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	if err := job.Validate(); err != nil {
		t.Fatalf("valid job should pass validation: %v", err)
	}
}

func TestValidate_EmptyID(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	job.Id = ""
	if err := job.Validate(); err == nil {
		t.Fatal("job with empty ID should fail validation")
	}
}

func TestValidate_ShortModelHash(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	job.ModelHash = make([]byte, 16) // too short
	if err := job.Validate(); err == nil {
		t.Fatal("job with 16-byte model hash should fail validation")
	}
}

func TestValidate_ShortInputHash(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	job.InputHash = make([]byte, 16) // too short
	if err := job.Validate(); err == nil {
		t.Fatal("job with 16-byte input hash should fail validation")
	}
}

func TestValidate_EmptyPurpose(t *testing.T) {
	job := makeTestJob(types.JobStatusPending)
	job.Purpose = ""
	if err := job.Validate(); err == nil {
		t.Fatal("job with empty purpose should fail validation")
	}
}

// =============================================================================
// DEFAULT EXPIRY BLOCKS CONSTANT
// =============================================================================

func TestDefaultJobExpiryBlocks_Is24Hours(t *testing.T) {
	// At ~6s block time, 14400 blocks ≈ 86400 seconds ≈ 24 hours
	expectedBlocks := int64(14400)
	if types.DefaultJobExpiryBlocks != expectedBlocks {
		t.Fatalf("DefaultJobExpiryBlocks should be %d, got %d",
			expectedBlocks, types.DefaultJobExpiryBlocks)
	}
}

// =============================================================================
// POLICY: ValidTransitions Map Completeness
// =============================================================================

func TestValidTransitions_AllStatesHaveEntries(t *testing.T) {
	allStatuses := []types.JobStatus{
		types.JobStatusPending,
		types.JobStatusProcessing,
		types.JobStatusCompleted,
		types.JobStatusFailed,
		types.JobStatusExpired,
	}

	for _, status := range allStatuses {
		if _, ok := types.ValidTransitions[status]; !ok {
			t.Errorf("ValidTransitions missing entry for status %s", status)
		}
	}
}

func TestValidTransitions_TerminalStatesHaveNoOutgoing(t *testing.T) {
	terminals := []types.JobStatus{
		types.JobStatusCompleted,
		types.JobStatusFailed,
		types.JobStatusExpired,
	}

	for _, status := range terminals {
		transitions := types.ValidTransitions[status]
		if len(transitions) != 0 {
			t.Errorf("terminal state %s should have 0 outgoing transitions, got %d",
				status, len(transitions))
		}
	}
}

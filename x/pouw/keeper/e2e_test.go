package keeper_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	metaRetryCount     = "scheduler.retry_count"
	metaAssignedTo     = "scheduler.assigned_to"
	metaLastAttempt    = "scheduler.last_attempt_block"
	metaSubmittedBlock = "scheduler.submitted_block"
)

// TestEndToEndConsensus tests the complete Proof-of-Useful-Work consensus flow
func TestEndToEndConsensus(t *testing.T) {
	// This test simulates the complete flow:
	// 1. Job submission
	// 2. Validator registration
	// 3. Job scheduling
	// 4. Vote extension creation
	// 5. Vote aggregation
	// 6. Consensus determination
	// 7. Seal transaction creation

	t.Log("=== End-to-End Proof-of-Useful-Work Consensus Test ===")

	// Setup
	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	// Create scheduler with realistic config
	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Create consensus handler
	consensusHandler := createTestConsensusHandler(logger, scheduler)

	// Step 1: Register validators with different capabilities
	t.Log("Step 1: Registering validators...")
	validators := registerTestValidators(scheduler)
	t.Logf("Registered %d validators", len(validators))

	// Step 2: Create and submit compute jobs
	t.Log("Step 2: Submitting compute jobs...")
	jobs := submitTestJobs(ctx, scheduler)
	t.Logf("Submitted %d jobs", len(jobs))

	// Step 3: Schedule jobs for processing
	t.Log("Step 3: Scheduling jobs...")
	scheduledJobs := scheduler.GetNextJobs(ctx, 100)
	t.Logf("Scheduled %d jobs for processing", len(scheduledJobs))

	// Step 4: Each validator creates vote extensions
	t.Log("Step 4: Creating vote extensions...")
	voteExtensions := createVoteExtensions(validators, jobs, 100)
	t.Logf("Created %d vote extensions", len(voteExtensions))

	// Step 5: Convert to ABCI vote info
	t.Log("Step 5: Converting to ABCI votes...")
	abciVotes := convertToABCIVotes(voteExtensions)

	// Step 6: Aggregate votes and determine consensus
	t.Log("Step 6: Aggregating votes and determining consensus...")
	results := consensusHandler.AggregateTestVotes(abciVotes, 67)
	t.Logf("Aggregated results for %d jobs", len(results))

	// Step 7: Check consensus results
	t.Log("Step 7: Checking consensus results...")
	consensusCount := 0
	for jobID, result := range results {
		if result.HasConsensus {
			consensusCount++
			t.Logf("Job %s reached consensus with %d/%d validators",
				jobID, result.AgreementCount, result.TotalVotes)
		} else {
			t.Logf("Job %s did NOT reach consensus", jobID)
		}
	}

	// Step 8: Create seal transactions for jobs with consensus
	t.Log("Step 8: Creating seal transactions...")
	sealTxs := createSealTransactions(results, 100)
	t.Logf("Created %d seal transactions", len(sealTxs))

	// Step 9: Validate seal transactions
	t.Log("Step 9: Validating seal transactions...")
	for i, tx := range sealTxs {
		if !keeper.IsSealTransaction(tx) {
			t.Errorf("Seal transaction %d is not valid", i)
		}
	}

	// Step 10: Verify final state
	t.Log("Step 10: Verifying final state...")
	stats := scheduler.GetQueueStats()
	t.Logf("Final queue stats: %d total jobs, %d pending, %d processing",
		stats.TotalJobs, stats.PendingJobs, stats.ProcessingJobs)

	// Assertions
	if consensusCount == 0 && len(scheduledJobs) > 0 {
		t.Error("Expected at least one job to reach consensus")
	}

	if len(sealTxs) != consensusCount {
		t.Errorf("Expected %d seal transactions, got %d", consensusCount, len(sealTxs))
	}

	t.Log("=== End-to-End Test Complete ===")
}

// TestConsensusWithByzantineValidators tests consensus with some validators providing wrong results
func TestConsensusWithByzantineValidators(t *testing.T) {
	t.Log("=== Byzantine Fault Tolerance Test ===")

	// Setup
	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Register 5 validators
	validators := []string{"val1", "val2", "val3", "val4", "val5"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	// Create a test job
	modelHash := randomHash()
	inputHash := randomHash()
	job := &types.ComputeJob{
		Id:          "byzantine-test-job",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "cosmos1test",
		ProofType:   types.ProofTypeTEE,
		Purpose:     "byzantine-test",
		Status:      types.JobStatusPending,
		Priority:    10,
	}

	scheduler.EnqueueJob(ctx, job)

	// Correct output (what honest validators report)
	correctOutput := computeCorrectOutput(modelHash, inputHash)

	// Byzantine output (what malicious validators report)
	byzantineOutput := randomHash()

	// Create vote extensions - 4 honest, 1 byzantine
	var voteExtensions []*keeper.VoteExtensionWire

	// 4 honest validators (meets 2/3+1 threshold for 5 validators)
	for i := 0; i < 4; i++ {
		ext := createSingleVoteExtension(validators[i], 100, job.Id, modelHash, inputHash, correctOutput, true)
		voteExtensions = append(voteExtensions, ext)
	}

	// 1 byzantine validator
	for i := 4; i < 5; i++ {
		ext := createSingleVoteExtension(validators[i], 100, job.Id, modelHash, inputHash, byzantineOutput, true)
		voteExtensions = append(voteExtensions, ext)
	}

	// Convert to ABCI votes
	abciVotes := convertToABCIVotes(voteExtensions)

	// Aggregate and check consensus
	results := aggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Fatal("No result for job")
	}

	// Should reach consensus with honest validators
	if !result.HasConsensus {
		t.Error("Expected consensus to be reached despite byzantine validators")
	}

	// Should use correct output
	if !bytesEqual(result.OutputHash, correctOutput) {
		t.Error("Consensus output should be the correct output from honest validators")
	}

	// Should have 4 agreeing validators
	if result.AgreementCount != 4 {
		t.Errorf("Expected 4 honest validators to agree, got %d", result.AgreementCount)
	}

	t.Log("Byzantine fault tolerance test passed - honest majority prevailed")
}

// TestConsensusFailure tests when consensus cannot be reached
func TestConsensusFailure(t *testing.T) {
	t.Log("=== Consensus Failure Test ===")

	// Setup
	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Register 5 validators
	validators := []string{"val1", "val2", "val3", "val4", "val5"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	// Create a test job
	job := &types.ComputeJob{
		Id:          "failure-test-job",
		ModelHash:   randomHash(),
		InputHash:   randomHash(),
		RequestedBy: "cosmos1test",
		ProofType:   types.ProofTypeTEE,
		Purpose:     "failure-test",
		Status:      types.JobStatusPending,
		Priority:    10,
	}

	scheduler.EnqueueJob(ctx, job)

	// Each validator reports a different output (no consensus possible)
	var voteExtensions []*keeper.VoteExtensionWire
	for _, v := range validators {
		ext := createSingleVoteExtension(v, 100, job.Id, job.ModelHash, job.InputHash, randomHash(), true)
		voteExtensions = append(voteExtensions, ext)
	}

	// Convert to ABCI votes
	abciVotes := convertToABCIVotes(voteExtensions)

	// Aggregate
	results := aggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Log("No result returned when no consensus - expected behavior")
		return
	}

	if result.HasConsensus {
		t.Error("Expected consensus to fail when all validators disagree")
	}

	t.Log("Consensus failure test passed - correctly detected no consensus")
}

// TestJobPriorityProcessing tests that high priority jobs are processed first
func TestJobPriorityProcessing(t *testing.T) {
	t.Log("=== Job Priority Processing Test ===")

	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 1
	config.MaxJobsPerBlock = 2 // Only process 2 jobs per block
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Register validator
	scheduler.RegisterValidator(&types.ValidatorCapability{
		Address:           "validator1",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 10,
		IsOnline:          true,
		ReputationScore:   80,
	})

	// Submit jobs with different priorities
	jobs := []*types.ComputeJob{
		createTestJob("low-priority", types.ProofTypeTEE, 1),
		createTestJob("medium-priority", types.ProofTypeTEE, 50),
		createTestJob("high-priority", types.ProofTypeTEE, 100),
		createTestJob("critical-priority", types.ProofTypeTEE, 1000),
	}

	for _, job := range jobs {
		scheduler.EnqueueJob(ctx, job)
	}

	// Get next jobs - should be highest priority first
	selectedJobs := scheduler.GetNextJobs(ctx, 100)

	if len(selectedJobs) < 2 {
		t.Fatalf("Expected at least 2 jobs selected, got %d", len(selectedJobs))
	}

	// First job should be highest priority
	if selectedJobs[0].Id != "critical-priority" {
		t.Errorf("Expected 'critical-priority' first, got '%s'", selectedJobs[0].Id)
	}

	// Second should be high priority
	if selectedJobs[1].Id != "high-priority" {
		t.Errorf("Expected 'high-priority' second, got '%s'", selectedJobs[1].Id)
	}

	t.Log("Priority processing test passed")
}

// TestEndToEnd_ChainBackedSchedulerFlow exercises keeper-backed scheduling with
// validator capabilities loaded from on-chain state and metadata persistence.
func TestEndToEnd_ChainBackedSchedulerFlow(t *testing.T) {
	t.Log("=== Chain-Backed Scheduler E2E Test ===")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true // permits legacy entropy fallback in deterministic tests
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 2
	config.MaxJobsPerBlock = 10
	scheduler := keeper.NewJobScheduler(logger, &k, config)

	// Register validator capabilities in keeper (on-chain state)
	validators := []*types.ValidatorCapability{
		{Address: "val-tee-1", TeePlatforms: []string{"aws-nitro"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 80},
		{Address: "val-tee-2", TeePlatforms: []string{"aws-nitro"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 75},
		{Address: "val-zkml-1", ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 70},
		{Address: "val-hybrid-1", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 90},
		{Address: "val-hybrid-2", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 85},
	}
	for _, cap := range validators {
		if err := k.RegisterValidatorCapability(ctx, cap); err != nil {
			t.Fatalf("register validator capability: %v", err)
		}
	}

	// Submit jobs via keeper (on-chain state)
	jobs := []*types.ComputeJob{
		createTestJob("tee-job", types.ProofTypeTEE, 10),
		createTestJob("zkml-job", types.ProofTypeZKML, 10),
		createTestJob("hybrid-job", types.ProofTypeHybrid, 10),
	}
	for _, job := range jobs {
		job.RequestedBy = validRequester(job.Id)
		registerModelForJob(t, ctx, k, job)
		if err := k.SubmitJob(ctx, job); err != nil {
			t.Fatalf("submit job %s: %v", job.Id, err)
		}
	}

	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync from chain: %v", err)
	}

	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	if len(selected) != len(jobs) {
		t.Fatalf("expected %d jobs selected, got %d", len(jobs), len(selected))
	}

	// Ensure scheduling metadata is persisted to on-chain job state.
	for _, job := range selected {
		stored, err := k.GetJob(ctx, job.Id)
		if err != nil {
			t.Fatalf("get job %s: %v", job.Id, err)
		}
		if stored.Status != types.JobStatusProcessing {
			t.Errorf("job %s should be processing, got %s", job.Id, stored.Status)
		}
		if stored.Metadata == nil {
			t.Errorf("job %s metadata not persisted", job.Id)
			continue
		}
		if stored.Metadata[metaLastAttempt] == "" || stored.Metadata[metaSubmittedBlock] == "" {
			t.Errorf("job %s missing scheduling metadata", job.Id)
		}
		if stored.Metadata[metaAssignedTo] == "" {
			t.Errorf("job %s missing assigned_to metadata", job.Id)
		}
	}

	// Hybrid job should only be assigned to validators with both TEE and zkML.
	hybridStored, err := k.GetJob(ctx, "hybrid-job")
	if err != nil {
		t.Fatalf("get hybrid job: %v", err)
	}
	var assigned []string
	if err := json.Unmarshal([]byte(hybridStored.Metadata[metaAssignedTo]), &assigned); err != nil {
		t.Fatalf("decode assigned validators: %v", err)
	}
	if len(assigned) < config.MinValidatorsRequired {
		t.Fatalf("hybrid job assigned %d validators, expected at least %d", len(assigned), config.MinValidatorsRequired)
	}
	allowed := map[string]bool{
		"val-hybrid-1": true,
		"val-hybrid-2": true,
	}
	for _, addr := range assigned {
		if !allowed[addr] {
			t.Fatalf("hybrid job assigned invalid validator: %s", addr)
		}
	}
}

// TestEndToEnd_RetryAndFailurePath exercises retry logic and persistence.
func TestEndToEnd_RetryAndFailurePath(t *testing.T) {
	t.Log("=== Retry and Failure Path E2E Test ===")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true // deterministic test path without drand beacon
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 1
	config.MaxRetries = 2
	scheduler := keeper.NewJobScheduler(logger, &k, config)

	cap := &types.ValidatorCapability{
		Address:           "val-tee-1",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 5,
		IsOnline:          true,
		ReputationScore:   80,
	}
	if err := k.RegisterValidatorCapability(ctx, cap); err != nil {
		t.Fatalf("register validator capability: %v", err)
	}

	job := createTestJob("retry-job", types.ProofTypeTEE, 10)
	job.RequestedBy = validRequester(job.Id)
	registerModelForJob(t, ctx, k, job)
	if err := k.SubmitJob(ctx, job); err != nil {
		t.Fatalf("submit job: %v", err)
	}

	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync from chain: %v", err)
	}

	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	if len(selected) != 1 {
		t.Fatalf("expected 1 job selected, got %d", len(selected))
	}

	scheduler.MarkJobFailedWithContext(ctx, job.Id, "boom-1")
	stored, err := k.GetJob(ctx, job.Id)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if stored.Status != types.JobStatusPending {
		t.Fatalf("expected job to be pending after retry, got %s", stored.Status)
	}
	if stored.Metadata[metaRetryCount] != "1" {
		t.Fatalf("expected retry_count=1, got %q", stored.Metadata[metaRetryCount])
	}

	ctxNext := ctx.WithBlockHeight(ctx.BlockHeight() + 1)
	selected = scheduler.GetNextJobs(ctxNext, ctxNext.BlockHeight())
	if len(selected) != 1 {
		t.Fatalf("expected job to be reselected, got %d", len(selected))
	}

	scheduler.MarkJobFailedWithContext(ctxNext, job.Id, "boom-2")
	stored, err = k.GetJob(ctxNext, job.Id)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if stored.Status != types.JobStatusFailed {
		t.Fatalf("expected job to be failed after max retries, got %s", stored.Status)
	}
	if stored.Metadata[metaRetryCount] != "2" {
		t.Fatalf("expected retry_count=2, got %q", stored.Metadata[metaRetryCount])
	}
	if _, ok := stored.Metadata[metaAssignedTo]; ok {
		t.Fatalf("expected assigned_to to be cleared after failure")
	}

	ctxFinal := ctxNext.WithBlockHeight(ctxNext.BlockHeight() + 1)
	selected = scheduler.GetNextJobs(ctxFinal, ctxFinal.BlockHeight())
	if len(selected) != 0 {
		t.Fatalf("expected no jobs selected after permanent failure, got %d", len(selected))
	}
}

// Helper functions for e2e tests

func createTestConsensusHandler(logger log.Logger, scheduler *keeper.JobScheduler) *testConsensusHandler {
	return &testConsensusHandler{
		logger:    logger,
		scheduler: scheduler,
	}
}

type testConsensusHandler struct {
	logger    log.Logger
	scheduler *keeper.JobScheduler
}

func (tch *testConsensusHandler) AggregateTestVotes(votes []abci.ExtendedVoteInfo, threshold int) map[string]*keeper.AggregatedResult {
	return aggregateTestVotes(votes, threshold)
}

func registerTestValidators(scheduler *keeper.JobScheduler) []string {
	validators := []string{
		"cosmosvaloper1validator1",
		"cosmosvaloper1validator2",
		"cosmosvaloper1validator3",
		"cosmosvaloper1validator4",
		"cosmosvaloper1validator5",
	}

	for i, v := range validators {
		cap := &types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   int64(70 + i*5), // Varying reputation
		}

		// Some validators also support zkML
		if i%2 == 0 {
			cap.ZkmlSystems = []string{"ezkl"}
		}

		scheduler.RegisterValidator(cap)
	}

	return validators
}

func submitTestJobs(ctx context.Context, scheduler *keeper.JobScheduler) []*types.ComputeJob {
	jobs := []*types.ComputeJob{
		createTestJob("tee-job-1", types.ProofTypeTEE, 10),
		createTestJob("tee-job-2", types.ProofTypeTEE, 20),
		createTestJob("zkml-job-1", types.ProofTypeZKML, 15),
		createTestJob("hybrid-job-1", types.ProofTypeHybrid, 25),
	}

	for _, job := range jobs {
		scheduler.EnqueueJob(ctx, job)
	}

	return jobs
}

func createVoteExtensions(validators []string, jobs []*types.ComputeJob, height int64) []*keeper.VoteExtensionWire {
	var extensions []*keeper.VoteExtensionWire

	for _, v := range validators {
		var verifications []keeper.VerificationWire

		for _, job := range jobs {
			// All validators compute the same deterministic output
			outputHash := computeCorrectOutput(job.ModelHash, job.InputHash)

			verification := keeper.VerificationWire{
				JobID:           job.Id,
				ModelHash:       job.ModelHash,
				InputHash:       job.InputHash,
				OutputHash:      outputHash,
				AttestationType: "tee",
				TEEAttestation:  json.RawMessage([]byte(fmt.Sprintf("\"%x\"", randomBytes(16)))),
				ExecutionTimeMs: 100,
				Success:         true,
			}

			verifications = append(verifications, verification)
		}

		validatorAddr, _ := json.Marshal(v)
		ext := &keeper.VoteExtensionWire{
			Version:          1,
			Height:           height,
			ValidatorAddress: validatorAddr,
			Verifications:    verifications,
			Timestamp:        time.Now().UTC(),
		}

		extensions = append(extensions, ext)
	}

	return extensions
}

func createSingleVoteExtension(validator string, height int64, jobID string, modelHash, inputHash, outputHash []byte, success bool) *keeper.VoteExtensionWire {
	verification := keeper.VerificationWire{
		JobID:           jobID,
		ModelHash:       modelHash,
		InputHash:       inputHash,
		OutputHash:      outputHash,
		AttestationType: "tee",
		TEEAttestation:  json.RawMessage([]byte(fmt.Sprintf("\"%x\"", randomBytes(16)))),
		ExecutionTimeMs: 100,
		Success:         success,
	}

	validatorAddr, _ := json.Marshal(validator)
	return &keeper.VoteExtensionWire{
		Version:          1,
		Height:           height,
		ValidatorAddress: validatorAddr,
		Verifications:    []keeper.VerificationWire{verification},
		Timestamp:        time.Now().UTC(),
	}
}

func convertToABCIVotes(extensions []*keeper.VoteExtensionWire) []abci.ExtendedVoteInfo {
	var votes []abci.ExtendedVoteInfo

	for _, ext := range extensions {
		data, _ := json.Marshal(ext)
		votes = append(votes, abci.ExtendedVoteInfo{
			VoteExtension: data,
		})
	}

	return votes
}

func createSealTransactions(results map[string]*keeper.AggregatedResult, height int64) [][]byte {
	var txs [][]byte

	for _, result := range results {
		if !result.HasConsensus {
			continue
		}

		sealTx := keeper.SealCreationTx{
			Type:             "create_seal_from_consensus",
			JobID:            result.JobID,
			ModelHash:        result.ModelHash,
			InputHash:        result.InputHash,
			OutputHash:       result.OutputHash,
			ValidatorCount:   result.AgreementCount,
			TotalVotes:       result.TotalVotes,
			AgreementPower:   result.AgreementPower,
			TotalPower:       result.TotalPower,
			ValidatorResults: result.ValidatorResults,
			BlockHeight:      height,
			Timestamp:        time.Now().UTC(),
		}

		data, _ := json.Marshal(sealTx)
		txs = append(txs, data)
	}

	return txs
}

func registerModelForJob(t *testing.T, ctx sdk.Context, k keeper.Keeper, job *types.ComputeJob) {
	t.Helper()
	model := &types.RegisteredModel{
		ModelHash: job.ModelHash,
		ModelId:   job.Id,
		Name:      fmt.Sprintf("model-%s", job.Id),
		Owner:     job.RequestedBy,
	}
	if err := k.RegisterModel(ctx, model); err != nil {
		t.Fatalf("register model: %v", err)
	}
}

func validRequester(seed string) string {
	hash := sha256.Sum256([]byte(seed))
	return sdk.AccAddress(hash[:20]).String()
}

func computeCorrectOutput(modelHash, inputHash []byte) []byte {
	combined := append(modelHash, inputHash...)
	combined = append(combined, []byte("aethelred_compute_v1")...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// BenchmarkVoteAggregation benchmarks the vote aggregation performance
func BenchmarkVoteAggregation(b *testing.B) {
	// Create test data
	numValidators := 100
	numJobs := 10

	var voteExtensions []*keeper.VoteExtensionWire
	for v := 0; v < numValidators; v++ {
		var verifications []keeper.VerificationWire

		for j := 0; j < numJobs; j++ {
			modelHash := randomHash()
			inputHash := randomHash()
			outputHash := computeCorrectOutput(modelHash, inputHash)

			verifications = append(verifications, keeper.VerificationWire{
				JobID:           fmt.Sprintf("job-%d", j),
				ModelHash:       modelHash,
				InputHash:       inputHash,
				OutputHash:      outputHash,
				AttestationType: "tee",
				TEEAttestation:  json.RawMessage([]byte("\"attestation\"")),
				ExecutionTimeMs: 100,
				Success:         true,
			})
		}

		validatorAddr, _ := json.Marshal(fmt.Sprintf("validator%d", v))
		ext := &keeper.VoteExtensionWire{
			Version:          1,
			Height:           100,
			ValidatorAddress: validatorAddr,
			Verifications:    verifications,
			Timestamp:        time.Now().UTC(),
		}

		voteExtensions = append(voteExtensions, ext)
	}

	abciVotes := convertToABCIVotes(voteExtensions)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		aggregateTestVotes(abciVotes, 67)
	}
}

// BenchmarkSchedulerEnqueue benchmarks job enqueueing performance
func BenchmarkSchedulerEnqueue(b *testing.B) {
	ctx := sdkTestContext()
	logger := log.NewNopLogger()
	scheduler := keeper.NewJobScheduler(logger, nil, keeper.DefaultSchedulerConfig())

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		job := &types.ComputeJob{
			Id:          fmt.Sprintf("job-%d", i),
			ModelHash:   randomHash(),
			InputHash:   randomHash(),
			RequestedBy: "cosmos1test",
			ProofType:   types.ProofTypeTEE,
			Purpose:     "benchmark",
			Status:      types.JobStatusPending,
			Priority:    int64(i % 100),
		}

		scheduler.EnqueueJob(ctx, job)
	}
}

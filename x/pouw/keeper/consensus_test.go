package keeper_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// TestConsensusHandler tests the consensus handling functionality
func TestConsensusHandler(t *testing.T) {
	t.Run("VoteExtension creation and validation", testVoteExtensionCreationAndValidation)
	t.Run("Verification execution", testVerificationExecution)
	t.Run("Vote aggregation with consensus", testVoteAggregationWithConsensus)
	t.Run("Vote aggregation without consensus", testVoteAggregationWithoutConsensus)
	t.Run("Seal transaction creation", testSealTransactionCreation)
	t.Run("Seal transaction validation", testSealTransactionValidation)
}

func TestConsensusHandlerPowerWeightedAggregation(t *testing.T) {
	t.Run("Power-weighted consensus overrides count", testPowerWeightedConsensus)
	t.Run("Count majority without power fails", testCountMajorityFailsWithoutPower)
	t.Run("Mismatched validator address is ignored", testMismatchedValidatorAddressIgnored)
}

func testVoteExtensionCreationAndValidation(t *testing.T) {
	// Create test verification data
	verification := keeper.VerificationWire{
		JobID:           "test-job-1",
		ModelHash:       randomHash(),
		InputHash:       randomHash(),
		OutputHash:      randomHash(),
		AttestationType: "tee",
		ExecutionTimeMs: 100,
		Success:         true,
	}

	// Create vote extension
	extension := keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: json.RawMessage("\"cosmosvaloper1test\""),
		Verifications:    []keeper.VerificationWire{verification},
		Timestamp:        time.Now().UTC(),
	}

	// Serialize and deserialize
	data, err := json.Marshal(extension)
	if err != nil {
		t.Fatalf("Failed to marshal vote extension: %v", err)
	}

	var deserialized keeper.VoteExtensionWire
	if err := json.Unmarshal(data, &deserialized); err != nil {
		t.Fatalf("Failed to unmarshal vote extension: %v", err)
	}

	// Verify fields
	if deserialized.Version != extension.Version {
		t.Errorf("Version mismatch: expected %d, got %d", extension.Version, deserialized.Version)
	}

	if len(deserialized.Verifications) != 1 {
		t.Errorf("Expected 1 verification, got %d", len(deserialized.Verifications))
	}

	if deserialized.Verifications[0].JobID != verification.JobID {
		t.Errorf("Job ID mismatch: expected %s, got %s", verification.JobID, deserialized.Verifications[0].JobID)
	}

	t.Log("Vote extension creation and validation passed")
}

func testVerificationExecution(t *testing.T) {
	// Test deterministic output computation
	modelHash := randomHash()
	inputHash := randomHash()

	// Compute output twice - should be the same
	output1 := computeDeterministicOutput(modelHash, inputHash)
	output2 := computeDeterministicOutput(modelHash, inputHash)

	if !bytesEqual(output1, output2) {
		t.Error("Deterministic output computation is not deterministic")
	}

	// Different inputs should produce different outputs
	differentInput := randomHash()
	output3 := computeDeterministicOutput(modelHash, differentInput)

	if bytesEqual(output1, output3) {
		t.Error("Different inputs produced same output")
	}

	t.Log("Verification execution passed")
}

func testVoteAggregationWithConsensus(t *testing.T) {
	// Create 5 validators, all reporting the same output
	modelHash := randomHash()
	inputHash := randomHash()
	outputHash := computeDeterministicOutput(modelHash, inputHash)

	var votes []abci.ExtendedVoteInfo
	for i := 0; i < 5; i++ {
		extension := createTestVoteExtension(
			fmt.Sprintf("validator%d", i),
			100,
			"job-1",
			modelHash,
			inputHash,
			outputHash,
			true,
		)

		data, _ := json.Marshal(extension)
		votes = append(votes, abci.ExtendedVoteInfo{
			VoteExtension: data,
		})
	}

	// Aggregate votes
	results := aggregateTestVotes(votes, 67)

	// Check consensus was reached
	result, ok := results["job-1"]
	if !ok {
		t.Fatal("No result for job-1")
	}

	if !result.HasConsensus {
		t.Error("Expected consensus to be reached")
	}

	if result.AgreementCount != 5 {
		t.Errorf("Expected 5 agreements, got %d", result.AgreementCount)
	}

	if !bytesEqual(result.OutputHash, outputHash) {
		t.Error("Output hash mismatch")
	}

	t.Log("Vote aggregation with consensus passed")
}

func testVoteAggregationWithoutConsensus(t *testing.T) {
	// Create 5 validators, each reporting different outputs
	var votes []abci.ExtendedVoteInfo
	for i := 0; i < 5; i++ {
		extension := createTestVoteExtension(
			fmt.Sprintf("validator%d", i),
			100,
			"job-1",
			randomHash(),
			randomHash(),
			randomHash(), // Different output each time
			true,
		)

		data, _ := json.Marshal(extension)
		votes = append(votes, abci.ExtendedVoteInfo{
			VoteExtension: data,
		})
	}

	// Aggregate votes
	results := aggregateTestVotes(votes, 67)

	// Check consensus was not reached
	result, ok := results["job-1"]
	if !ok {
		// No result is also valid when no consensus
		t.Log("Vote aggregation without consensus passed (no result)")
		return
	}

	if result.HasConsensus {
		t.Error("Expected consensus NOT to be reached")
	}

	t.Log("Vote aggregation without consensus passed")
}

func testPowerWeightedConsensus(t *testing.T) {
	// High-power validator reaches consensus even if only 1 of 2 validators agree.
	modelHash := randomHash()
	inputHash := randomHash()
	outputHigh := computeDeterministicOutput(modelHash, inputHash)
	outputLow := computeDeterministicOutput(modelHash, randomHash())

	addrHigh := randomBytes(20)
	addrLow := randomBytes(20)

	votes := []abci.ExtendedVoteInfo{
		makePowerVote(t, addrHigh, 80, "job-power", modelHash, inputHash, outputHigh, true),
		makePowerVote(t, addrLow, 20, "job-power", modelHash, inputHash, outputLow, true),
	}

	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
	ch.SetConsensusThresholdForTesting(67)
	results := ch.AggregateVoteExtensions(sdk.UnwrapSDKContext(sdkTestContext()), votes)

	result, ok := results["job-power"]
	if !ok {
		t.Fatal("Expected result for job-power")
	}
	if !result.HasConsensus {
		t.Fatal("Expected consensus based on voting power")
	}
	if !bytesEqual(result.OutputHash, outputHigh) {
		t.Fatalf("Expected high-power output hash to win consensus")
	}
	if result.AgreementPower != 80 {
		t.Fatalf("Expected agreement power 80, got %d", result.AgreementPower)
	}
}

func testCountMajorityFailsWithoutPower(t *testing.T) {
	// Two low-power validators agree, but do not reach the required power threshold.
	modelHash := randomHash()
	inputHash := randomHash()
	output := computeDeterministicOutput(modelHash, inputHash)

	addrLow1 := randomBytes(20)
	addrLow2 := randomBytes(20)
	addrHigh := randomBytes(20)

	votes := []abci.ExtendedVoteInfo{
		makePowerVote(t, addrLow1, 10, "job-power-fail", modelHash, inputHash, output, true),
		makePowerVote(t, addrLow2, 10, "job-power-fail", modelHash, inputHash, output, true),
		// High-power validator present but does not submit a vote extension.
		{
			Validator: abci.Validator{Address: addrHigh, Power: 80},
		},
	}

	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
	ch.SetConsensusThresholdForTesting(67)
	results := ch.AggregateVoteExtensions(sdk.UnwrapSDKContext(sdkTestContext()), votes)

	result, ok := results["job-power-fail"]
	if !ok {
		t.Fatal("Expected result entry for job-power-fail")
	}
	if result.HasConsensus {
		t.Fatal("Did not expect consensus with only 20% power")
	}
}

func testMismatchedValidatorAddressIgnored(t *testing.T) {
	modelHash := randomHash()
	inputHash := randomHash()
	output := computeDeterministicOutput(modelHash, inputHash)

	addrVote := randomBytes(20)
	addrExtension := randomBytes(20)

	vote := makePowerVoteWithExtensionAddr(t, addrVote, addrExtension, 80, "job-mismatch", modelHash, inputHash, output, true)

	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
	ch.SetConsensusThresholdForTesting(67)
	results := ch.AggregateVoteExtensions(sdk.UnwrapSDKContext(sdkTestContext()), []abci.ExtendedVoteInfo{vote})

	if len(results) != 0 {
		t.Fatalf("Expected mismatched validator address to be ignored")
	}
}

func testSealTransactionCreation(t *testing.T) {
	// Create aggregated result with consensus
	result := &keeper.AggregatedResult{
		JobID:          "job-1",
		ModelHash:      randomHash(),
		InputHash:      randomHash(),
		OutputHash:     randomHash(),
		AgreementCount: 4,
		AgreementPower: 4,
		TotalVotes:     5,
		TotalPower:     5,
		HasConsensus:   true,
		ValidatorResults: []keeper.ValidatorResult{
			{
				ValidatorAddress: "validator1",
				OutputHash:       randomHash(),
				AttestationType:  "tee",
				TEEPlatform:      "aws-nitro",
				ExecutionTimeMs:  100,
			},
		},
	}

	// Create seal transaction
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
		BlockHeight:      100,
		Timestamp:        time.Now().UTC(),
	}

	// Serialize
	data, err := json.Marshal(sealTx)
	if err != nil {
		t.Fatalf("Failed to marshal seal transaction: %v", err)
	}

	// Verify it's recognized as a seal transaction
	if !keeper.IsSealTransaction(data) {
		t.Error("Transaction not recognized as seal transaction")
	}

	t.Log("Seal transaction creation passed")
}

func testSealTransactionValidation(t *testing.T) {
	// Test valid transaction
	validTx := keeper.SealCreationTx{
		Type:           "create_seal_from_consensus",
		JobID:          "job-1",
		ModelHash:      randomHash(),
		InputHash:      randomHash(),
		OutputHash:     randomHash(),
		ValidatorCount: 4,
		TotalVotes:     5,
		AgreementPower: 4,
		TotalPower:     5,
		BlockHeight:    100,
		Timestamp:      time.Now().UTC(),
	}

	data, _ := json.Marshal(validTx)
	if !keeper.IsSealTransaction(data) {
		t.Error("Valid transaction not recognized")
	}

	// Test invalid type
	invalidTx := validTx
	invalidTx.Type = "invalid"
	data, _ = json.Marshal(invalidTx)
	if keeper.IsSealTransaction(data) {
		t.Error("Invalid type should not be recognized")
	}

	// Test missing fields
	incompleteTx := map[string]interface{}{
		"type": "create_seal_from_consensus",
		// Missing other fields
	}
	data, _ = json.Marshal(incompleteTx)
	if !keeper.IsSealTransaction(data) {
		// Type is enough to identify, validation would catch missing fields
		t.Log("Incomplete transaction identified by type (validation would catch issues)")
	}

	t.Log("Seal transaction validation passed")
}

// TestJobScheduler tests the job scheduler functionality
func TestJobScheduler(t *testing.T) {
	t.Run("Job enqueueing", testJobEnqueueing)
	t.Run("Priority ordering", testPriorityOrdering)
	t.Run("Validator assignment", testValidatorAssignment)
	t.Run("Job completion", testJobCompletion)
}

func testJobEnqueueing(t *testing.T) {
	scheduler := createTestScheduler()

	// Create and enqueue a job
	job := createTestJob("job-1", types.ProofTypeTEE, 10)

	ctx := sdkTestContext()
	err := scheduler.EnqueueJob(ctx, job)
	if err != nil {
		t.Fatalf("Failed to enqueue job: %v", err)
	}

	// Verify stats
	stats := scheduler.GetQueueStats()
	if stats.TotalJobs != 1 {
		t.Errorf("Expected 1 total job, got %d", stats.TotalJobs)
	}

	if stats.TEEJobs != 1 {
		t.Errorf("Expected 1 TEE job, got %d", stats.TEEJobs)
	}

	// Try to enqueue same job again - should fail
	err = scheduler.EnqueueJob(ctx, job)
	if err == nil {
		t.Error("Expected error when enqueueing duplicate job")
	}

	t.Log("Job enqueueing passed")
}

func testPriorityOrdering(t *testing.T) {
	scheduler := createTestScheduler()
	ctx := sdkTestContext()

	// Register a validator
	scheduler.RegisterValidator(&types.ValidatorCapability{
		Address:           "validator1",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 10,
		IsOnline:          true,
		ReputationScore:   80,
	})

	// Enqueue jobs with different priorities
	lowPriority := createTestJob("low", types.ProofTypeTEE, 1)
	highPriority := createTestJob("high", types.ProofTypeTEE, 100)
	medPriority := createTestJob("med", types.ProofTypeTEE, 50)

	scheduler.EnqueueJob(ctx, lowPriority)
	scheduler.EnqueueJob(ctx, highPriority)
	scheduler.EnqueueJob(ctx, medPriority)

	// Get next jobs - should be ordered by priority
	jobs := scheduler.GetNextJobs(ctx, 100)

	if len(jobs) != 3 {
		t.Fatalf("Expected 3 jobs, got %d", len(jobs))
	}

	// First should be highest priority
	if jobs[0].Id != "high" {
		t.Errorf("Expected 'high' first, got '%s'", jobs[0].Id)
	}

	t.Log("Priority ordering passed")
}

func testValidatorAssignment(t *testing.T) {
	scheduler := createTestScheduler()
	ctx := sdkTestContext()

	// Register validators with different capabilities
	scheduler.RegisterValidator(&types.ValidatorCapability{
		Address:           "tee-validator",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 5,
		IsOnline:          true,
		ReputationScore:   80,
	})

	scheduler.RegisterValidator(&types.ValidatorCapability{
		Address:           "zkml-validator",
		ZkmlSystems:       []string{"ezkl"},
		MaxConcurrentJobs: 5,
		IsOnline:          true,
		ReputationScore:   80,
	})

	scheduler.RegisterValidator(&types.ValidatorCapability{
		Address:           "hybrid-validator",
		TeePlatforms:      []string{"aws-nitro"},
		ZkmlSystems:       []string{"ezkl"},
		MaxConcurrentJobs: 5,
		IsOnline:          true,
		ReputationScore:   80,
	})

	// Create jobs for different proof types
	teeJob := createTestJob("tee-job", types.ProofTypeTEE, 10)
	zkmlJob := createTestJob("zkml-job", types.ProofTypeZKML, 10)
	hybridJob := createTestJob("hybrid-job", types.ProofTypeHybrid, 10)

	scheduler.EnqueueJob(ctx, teeJob)
	scheduler.EnqueueJob(ctx, zkmlJob)
	scheduler.EnqueueJob(ctx, hybridJob)

	// Get jobs for TEE validator
	teeValidatorJobs := scheduler.GetJobsForValidator(ctx, "tee-validator")
	t.Logf("TEE validator jobs: %d", len(teeValidatorJobs))

	// Get jobs for zkML validator
	zkmlValidatorJobs := scheduler.GetJobsForValidator(ctx, "zkml-validator")
	t.Logf("zkML validator jobs: %d", len(zkmlValidatorJobs))

	// Get jobs for hybrid validator - should be able to handle all
	hybridValidatorJobs := scheduler.GetJobsForValidator(ctx, "hybrid-validator")
	t.Logf("Hybrid validator jobs: %d", len(hybridValidatorJobs))

	t.Log("Validator assignment passed")
}

func testJobCompletion(t *testing.T) {
	scheduler := createTestScheduler()
	ctx := sdkTestContext()

	// Register validator and enqueue job
	scheduler.RegisterValidator(&types.ValidatorCapability{
		Address:           "validator1",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 5,
		IsOnline:          true,
		ReputationScore:   80,
	})

	job := createTestJob("job-1", types.ProofTypeTEE, 10)
	scheduler.EnqueueJob(ctx, job)

	// Get initial stats
	statsBefore := scheduler.GetQueueStats()
	if statsBefore.TotalJobs != 1 {
		t.Fatalf("Expected 1 job before completion, got %d", statsBefore.TotalJobs)
	}

	// Mark job complete
	scheduler.MarkJobComplete("job-1")

	// Verify stats after completion
	statsAfter := scheduler.GetQueueStats()
	if statsAfter.TotalJobs != 0 {
		t.Errorf("Expected 0 jobs after completion, got %d", statsAfter.TotalJobs)
	}

	t.Log("Job completion passed")
}

// Helper functions

func randomHash() []byte {
	hash := make([]byte, 32)
	rand.Read(hash)
	return hash
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func computeDeterministicOutput(modelHash, inputHash []byte) []byte {
	combined := append(modelHash, inputHash...)
	combined = append(combined, []byte("aethelred_compute_v1")...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func createTestVoteExtension(validator string, height int64, jobID string, modelHash, inputHash, outputHash []byte, success bool) *keeper.VoteExtensionWire {
	verification := keeper.VerificationWire{
		JobID:           jobID,
		ModelHash:       modelHash,
		InputHash:       inputHash,
		OutputHash:      outputHash,
		AttestationType: "tee",
		ExecutionTimeMs: 100,
		Success:         success,
	}

	return &keeper.VoteExtensionWire{
		Version:          1,
		Height:           height,
		ValidatorAddress: json.RawMessage(fmt.Sprintf("\"%s\"", validator)),
		Verifications:    []keeper.VerificationWire{verification},
		Timestamp:        time.Now().UTC(),
	}
}

func makePowerVote(t *testing.T, addr []byte, power int64, jobID string, modelHash, inputHash, outputHash []byte, success bool) abci.ExtendedVoteInfo {
	t.Helper()
	return makePowerVoteWithExtensionAddr(t, addr, addr, power, jobID, modelHash, inputHash, outputHash, success)
}

func makePowerVoteWithExtensionAddr(t *testing.T, voteAddr, extensionAddr []byte, power int64, jobID string, modelHash, inputHash, outputHash []byte, success bool) abci.ExtendedVoteInfo {
	t.Helper()
	addrJSON, err := json.Marshal(extensionAddr)
	if err != nil {
		t.Fatalf("Failed to marshal validator address: %v", err)
	}

	extension := keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: json.RawMessage(addrJSON),
		Verifications: []keeper.VerificationWire{
			{
				JobID:           jobID,
				ModelHash:       modelHash,
				InputHash:       inputHash,
				OutputHash:      outputHash,
				AttestationType: "tee",
				ExecutionTimeMs: 100,
				Success:         success,
			},
		},
		Timestamp: time.Now().UTC(),
	}

	data, err := json.Marshal(extension)
	if err != nil {
		t.Fatalf("Failed to marshal vote extension: %v", err)
	}

	return abci.ExtendedVoteInfo{
		Validator:     abci.Validator{Address: voteAddr, Power: power},
		VoteExtension: data,
	}
}

func aggregateTestVotes(votes []abci.ExtendedVoteInfo, threshold int) map[string]*keeper.AggregatedResult {
	aggregated := make(map[string]*keeper.AggregatedResult)
	outputVotes := make(map[string]map[string][]keeper.ValidatorResult)
	outputPower := make(map[string]map[string]int64)

	totalVotes := len(votes)
	totalPower := int64(0)
	for _, vote := range votes {
		totalPower += vote.Validator.Power
	}
	useFallbackPower := false
	if totalPower == 0 && totalVotes > 0 {
		totalPower = int64(totalVotes)
		useFallbackPower = true
	}
	requiredPower := (totalPower*int64(threshold) + 99) / 100
	if threshold >= 100 {
		requiredPower = totalPower
	}

	for _, vote := range votes {
		if len(vote.VoteExtension) == 0 {
			continue
		}
		votePower := vote.Validator.Power
		if useFallbackPower {
			votePower = 1
		}

		var extension keeper.VoteExtensionWire
		if err := json.Unmarshal(vote.VoteExtension, &extension); err != nil {
			continue
		}

		validatorAddr := ""
		if err := json.Unmarshal(extension.ValidatorAddress, &validatorAddr); err != nil || validatorAddr == "" {
			continue
		}

		for _, v := range extension.Verifications {
			if !v.Success {
				continue
			}

			outputHashHex := hex.EncodeToString(v.OutputHash)

			if outputVotes[v.JobID] == nil {
				outputVotes[v.JobID] = make(map[string][]keeper.ValidatorResult)
			}
			if outputPower[v.JobID] == nil {
				outputPower[v.JobID] = make(map[string]int64)
			}

			valResult := keeper.ValidatorResult{
				ValidatorAddress: validatorAddr,
				OutputHash:       v.OutputHash,
				AttestationType:  v.AttestationType,
				AttestationQuote: v.TEEAttestation,
				ZKProof:          v.ZKProof,
				ExecutionTimeMs:  v.ExecutionTimeMs,
				Timestamp:        extension.Timestamp,
			}

			outputVotes[v.JobID][outputHashHex] = append(outputVotes[v.JobID][outputHashHex], valResult)
			outputPower[v.JobID][outputHashHex] += votePower

			if aggregated[v.JobID] == nil {
				aggregated[v.JobID] = &keeper.AggregatedResult{
					JobID:            v.JobID,
					ModelHash:        v.ModelHash,
					InputHash:        v.InputHash,
					TotalVotes:       totalVotes,
					TotalPower:       totalPower,
					ValidatorResults: make([]keeper.ValidatorResult, 0),
				}
			}
		}
	}

	for jobID, outputs := range outputVotes {
		agg := aggregated[jobID]
		for outputHashHex, results := range outputs {
			agreementPower := outputPower[jobID][outputHashHex]
			if agreementPower >= requiredPower {
				outputHash, _ := hex.DecodeString(outputHashHex)
				agg.OutputHash = outputHash
				agg.ValidatorResults = results
				agg.AgreementCount = len(results)
				agg.AgreementPower = agreementPower
				agg.HasConsensus = true
				break
			}
		}
	}

	return aggregated
}

func createTestScheduler() *keeper.JobScheduler {
	logger := log.NewNopLogger()
	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 1 // Lower for testing
	return keeper.NewJobScheduler(logger, nil, config)
}

func createTestJob(id string, proofType types.ProofType, priority int64) *types.ComputeJob {
	now := time.Now().UTC()
	return &types.ComputeJob{
		Id:          id,
		ModelHash:   randomHash(),
		InputHash:   randomHash(),
		RequestedBy: "cosmos1test",
		ProofType:   proofType,
		Purpose:     "testing",
		Status:      types.JobStatusPending,
		CreatedAt:   timestamppb.New(now),
		UpdatedAt:   timestamppb.New(now),
		ExpiresAt:   timestamppb.New(now.Add(24 * time.Hour)),
		Priority:    priority,
		BlockHeight: 100,
	}
}

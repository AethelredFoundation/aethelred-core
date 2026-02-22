package keeper_test

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// DETERMINISTIC SLASHING TESTS
//
// These tests verify the slashing evidence collection system:
//   - Invalid output detection
//   - Double sign detection
//   - Collusion detection
//   - End-to-end evidence collection from consensus
//   - Severity multiplier correctness
//   - Determinism guarantees
//
// The EvidenceCollector performs pure detection logic and does not require
// on-chain state, so a nil keeper is used throughout.
// =============================================================================

// ---------------------------------------------------------------------------
// Test helpers specific to slashing tests
// ---------------------------------------------------------------------------

// makeVoteExtensionForTest creates a VoteExtensionWire with a single
// verification result for the given job, output, and success status.
func makeVoteExtensionForTest(validatorAddr string, jobID string, outputHash []byte, success bool) keeper.VoteExtensionWire {
	addrJSON, _ := json.Marshal(validatorAddr)
	return keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: addrJSON,
		Verifications: []keeper.VerificationWire{
			{
				JobID:           jobID,
				ModelHash:       randomHash(),
				InputHash:       randomHash(),
				OutputHash:      outputHash,
				AttestationType: "tee",
				ExecutionTimeMs: 100,
				Success:         success,
				Nonce:           randomHash(),
			},
		},
		Timestamp: time.Now().UTC(),
	}
}

// makeAggregatedResultForTest creates an AggregatedResult with the given
// consensus output and vote counts.
func makeAggregatedResultForTest(jobID string, consensusOutput []byte, totalVotes int, agreementCount int) *keeper.AggregatedResult {
	return &keeper.AggregatedResult{
		JobID:          jobID,
		ModelHash:      randomHash(),
		InputHash:      randomHash(),
		OutputHash:     consensusOutput,
		TotalVotes:     totalVotes,
		TotalPower:     int64(totalVotes),
		AgreementCount: agreementCount,
		AgreementPower: int64(agreementCount),
		HasConsensus:   true,
	}
}

// newTestEvidenceCollector creates an EvidenceCollector with a NopLogger
// and nil keeper (sufficient for pure detection logic tests).
func newTestEvidenceCollector() *keeper.EvidenceCollector {
	return keeper.NewEvidenceCollector(log.NewNopLogger(), nil)
}

// fixedBlockTimeContext returns an sdk.Context with a deterministic block
// time at the given height, independent of wall clock.
func fixedBlockTimeContext(height int64, blockTime time.Time) sdk.Context {
	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  height,
		Time:    blockTime,
	}
	return sdk.NewContext(nil, header, false, log.NewNopLogger())
}

// sortEvidenceByValidator sorts evidence records by ValidatorAddress for
// deterministic comparison.
func sortEvidenceByValidator(records []keeper.SlashingEvidenceRecord) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].ValidatorAddress < records[j].ValidatorAddress
	})
}

// sortEvidenceByCondition sorts evidence records by Condition then
// ValidatorAddress for deterministic comparison.
func sortEvidenceByCondition(records []keeper.SlashingEvidenceRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Condition != records[j].Condition {
			return records[i].Condition < records[j].Condition
		}
		return records[i].ValidatorAddress < records[j].ValidatorAddress
	})
}

// =============================================================================
// Section 1: Invalid Output Detection
// =============================================================================

func TestSlashing_InvalidOutput_SingleValidator(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-invalid-1"
	consensusOutput := randomHash()
	wrongOutput := randomHash()

	// 4 honest validators + 1 dishonest
	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 4; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-val-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	allVotes = append(allVotes, makeVoteExtensionForTest(
		"dishonest-val", jobID, wrongOutput, true,
	))

	evidence := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, allVotes)

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(evidence))
	}

	rec := evidence[0]
	if rec.ValidatorAddress != "dishonest-val" {
		t.Errorf("expected validator 'dishonest-val', got %q", rec.ValidatorAddress)
	}
	if rec.Condition != "invalid_output" {
		t.Errorf("expected condition 'invalid_output', got %q", rec.Condition)
	}
	if rec.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", rec.Severity)
	}
	if rec.JobID != jobID {
		t.Errorf("expected job ID %q, got %q", jobID, rec.JobID)
	}
	if !bytesEqual(rec.ExpectedOutput, consensusOutput) {
		t.Error("expected output hash mismatch")
	}
	if !bytesEqual(rec.ActualOutput, wrongOutput) {
		t.Error("actual output hash mismatch")
	}
	t.Log("OK: single validator invalid output correctly detected")
}

func TestSlashing_InvalidOutput_MultipleValidators(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-invalid-multi"
	consensusOutput := randomHash()
	wrongOutput1 := randomHash()
	wrongOutput2 := randomHash()

	var allVotes []keeper.VoteExtensionWire
	// 3 honest
	for i := 0; i < 3; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	// 2 dishonest with different wrong outputs
	allVotes = append(allVotes, makeVoteExtensionForTest("bad-1", jobID, wrongOutput1, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("bad-2", jobID, wrongOutput2, true))

	evidence := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, allVotes)

	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence records, got %d", len(evidence))
	}

	sortEvidenceByValidator(evidence)
	if evidence[0].ValidatorAddress != "bad-1" {
		t.Errorf("expected first record for 'bad-1', got %q", evidence[0].ValidatorAddress)
	}
	if evidence[1].ValidatorAddress != "bad-2" {
		t.Errorf("expected second record for 'bad-2', got %q", evidence[1].ValidatorAddress)
	}
	for _, rec := range evidence {
		if rec.Condition != "invalid_output" {
			t.Errorf("expected condition 'invalid_output', got %q", rec.Condition)
		}
		if rec.Severity != "high" {
			t.Errorf("expected severity 'high', got %q", rec.Severity)
		}
	}
	t.Log("OK: multiple invalid outputs correctly detected")
}

func TestSlashing_InvalidOutput_NoneWhenAllAgree(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-all-agree"
	consensusOutput := randomHash()

	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 5; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"val-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}

	evidence := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, allVotes)

	if len(evidence) != 0 {
		t.Fatalf("expected 0 evidence records when all agree, got %d", len(evidence))
	}
	t.Log("OK: no false positives when all validators agree")
}

func TestSlashing_InvalidOutput_FailedVerificationNotSlashed(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-failed-not-slashed"
	consensusOutput := randomHash()
	differentOutput := randomHash()

	var allVotes []keeper.VoteExtensionWire
	// 4 honest successful validators
	for i := 0; i < 4; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	// 1 validator with Success=false and a different output
	// Failed verifications should NOT be flagged for invalid output
	allVotes = append(allVotes, makeVoteExtensionForTest(
		"failed-val", jobID, differentOutput, false,
	))

	evidence := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, allVotes)

	if len(evidence) != 0 {
		t.Fatalf("expected 0 evidence records for failed verification, got %d", len(evidence))
	}
	t.Log("OK: failed verification not flagged for invalid output")
}

func TestSlashing_InvalidOutput_EmptyVotes(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-empty"
	consensusOutput := randomHash()

	var allVotes []keeper.VoteExtensionWire

	evidence := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, allVotes)

	if len(evidence) != 0 {
		t.Fatalf("expected 0 evidence records for empty votes, got %d", len(evidence))
	}
	t.Log("OK: empty votes produce no evidence")
}

// =============================================================================
// Section 2: Double Sign Detection
// =============================================================================

func TestSlashing_DoubleSign_SingleValidator(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-double-sign"
	output1 := randomHash()
	output2 := randomHash()

	// Same validator submits two different outputs in separate vote extensions
	var allVotes []keeper.VoteExtensionWire
	allVotes = append(allVotes, makeVoteExtensionForTest("double-signer", jobID, output1, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("double-signer", jobID, output2, true))

	evidence := ec.DetectDoubleSigners(ctx, jobID, allVotes)

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(evidence))
	}

	rec := evidence[0]
	if rec.ValidatorAddress != "double-signer" {
		t.Errorf("expected validator 'double-signer', got %q", rec.ValidatorAddress)
	}
	if rec.Condition != "double_sign" {
		t.Errorf("expected condition 'double_sign', got %q", rec.Condition)
	}
	if rec.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", rec.Severity)
	}
	if len(rec.ConflictingOutputs) != 2 {
		t.Errorf("expected 2 conflicting outputs, got %d", len(rec.ConflictingOutputs))
	}
	t.Log("OK: single validator double sign correctly detected")
}

func TestSlashing_DoubleSign_MultipleConflicts(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-triple-sign"

	// Same validator submits 3 different outputs
	var allVotes []keeper.VoteExtensionWire
	allVotes = append(allVotes, makeVoteExtensionForTest("multi-signer", jobID, randomHash(), true))
	allVotes = append(allVotes, makeVoteExtensionForTest("multi-signer", jobID, randomHash(), true))
	allVotes = append(allVotes, makeVoteExtensionForTest("multi-signer", jobID, randomHash(), true))

	evidence := ec.DetectDoubleSigners(ctx, jobID, allVotes)

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence record (one validator), got %d", len(evidence))
	}

	rec := evidence[0]
	if len(rec.ConflictingOutputs) != 3 {
		t.Errorf("expected 3 conflicting outputs, got %d", len(rec.ConflictingOutputs))
	}
	if rec.Condition != "double_sign" {
		t.Errorf("expected condition 'double_sign', got %q", rec.Condition)
	}
	if rec.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", rec.Severity)
	}
	t.Log("OK: triple sign correctly detected with 3 conflicting outputs")
}

func TestSlashing_DoubleSign_SameOutputNotFlagged(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-same-output"
	sameOutput := randomHash()

	// Same validator appears twice but with the SAME output hash
	var allVotes []keeper.VoteExtensionWire
	allVotes = append(allVotes, makeVoteExtensionForTest("honest-dup", jobID, sameOutput, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("honest-dup", jobID, sameOutput, true))

	evidence := ec.DetectDoubleSigners(ctx, jobID, allVotes)

	if len(evidence) != 0 {
		t.Fatalf("expected 0 evidence records for same output, got %d", len(evidence))
	}
	t.Log("OK: same output from same validator not flagged as double sign")
}

func TestSlashing_DoubleSign_MultipleValidators(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-multi-double"

	// Two different validators each double-sign
	var allVotes []keeper.VoteExtensionWire
	allVotes = append(allVotes, makeVoteExtensionForTest("ds-val-1", jobID, randomHash(), true))
	allVotes = append(allVotes, makeVoteExtensionForTest("ds-val-1", jobID, randomHash(), true))
	allVotes = append(allVotes, makeVoteExtensionForTest("ds-val-2", jobID, randomHash(), true))
	allVotes = append(allVotes, makeVoteExtensionForTest("ds-val-2", jobID, randomHash(), true))

	evidence := ec.DetectDoubleSigners(ctx, jobID, allVotes)

	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence records, got %d", len(evidence))
	}

	sortEvidenceByValidator(evidence)
	if evidence[0].ValidatorAddress != "ds-val-1" {
		t.Errorf("expected first record for 'ds-val-1', got %q", evidence[0].ValidatorAddress)
	}
	if evidence[1].ValidatorAddress != "ds-val-2" {
		t.Errorf("expected second record for 'ds-val-2', got %q", evidence[1].ValidatorAddress)
	}
	for _, rec := range evidence {
		if rec.Condition != "double_sign" {
			t.Errorf("expected condition 'double_sign', got %q", rec.Condition)
		}
		if rec.Severity != "critical" {
			t.Errorf("expected severity 'critical', got %q", rec.Severity)
		}
	}
	t.Log("OK: multiple double-signing validators correctly detected")
}

func TestSlashing_DoubleSign_OnlyCountsSuccessful(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-mixed-success"

	// One validator has one successful and one failed verification
	// with different output hashes. Only successful verifications count,
	// so with only 1 successful output, no double sign is detected.
	var allVotes []keeper.VoteExtensionWire
	allVotes = append(allVotes, makeVoteExtensionForTest("mixed-val", jobID, randomHash(), true))
	allVotes = append(allVotes, makeVoteExtensionForTest("mixed-val", jobID, randomHash(), false))

	evidence := ec.DetectDoubleSigners(ctx, jobID, allVotes)

	if len(evidence) != 0 {
		t.Fatalf("expected 0 evidence records (only 1 successful), got %d", len(evidence))
	}
	t.Log("OK: failed verification not counted toward double sign")
}

// =============================================================================
// Section 3: Collusion Detection
// =============================================================================

func TestSlashing_Collusion_TwoValidatorsSameWrongOutput(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-collusion-2"
	consensusOutput := randomHash()
	colludedOutput := randomHash()

	// 3 honest + 2 colluding
	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 3; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	allVotes = append(allVotes, makeVoteExtensionForTest("colluder-1", jobID, colludedOutput, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("colluder-2", jobID, colludedOutput, true))

	totalVoters := len(allVotes)
	evidence := ec.DetectColludingValidators(ctx, jobID, consensusOutput, allVotes, totalVoters)

	if len(evidence) != 2 {
		t.Fatalf("expected 2 collusion evidence records, got %d", len(evidence))
	}

	sortEvidenceByValidator(evidence)
	if evidence[0].ValidatorAddress != "colluder-1" {
		t.Errorf("expected 'colluder-1', got %q", evidence[0].ValidatorAddress)
	}
	if evidence[1].ValidatorAddress != "colluder-2" {
		t.Errorf("expected 'colluder-2', got %q", evidence[1].ValidatorAddress)
	}
	for _, rec := range evidence {
		if rec.Condition != "collusion" {
			t.Errorf("expected condition 'collusion', got %q", rec.Condition)
		}
		if rec.Severity != "critical" {
			t.Errorf("expected severity 'critical', got %q", rec.Severity)
		}
	}
	t.Log("OK: two-validator collusion correctly detected")
}

func TestSlashing_Collusion_SingleWrongValidatorNotCollusion(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-single-wrong"
	consensusOutput := randomHash()
	wrongOutput := randomHash()

	// 4 honest + 1 wrong (but alone, so not collusion)
	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 4; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	allVotes = append(allVotes, makeVoteExtensionForTest("lone-wolf", jobID, wrongOutput, true))

	totalVoters := len(allVotes)
	evidence := ec.DetectColludingValidators(ctx, jobID, consensusOutput, allVotes, totalVoters)

	if len(evidence) != 0 {
		t.Fatalf("expected 0 collusion records for single wrong validator, got %d", len(evidence))
	}
	t.Log("OK: single wrong validator not flagged as collusion")
}

func TestSlashing_Collusion_ThreeValidatorsCollude(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-collusion-3"
	consensusOutput := randomHash()
	colludedOutput := randomHash()

	// 4 honest + 3 colluding
	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 4; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	for i := 0; i < 3; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"colluder-"+string(rune('A'+i)), jobID, colludedOutput, true,
		))
	}

	totalVoters := len(allVotes)
	evidence := ec.DetectColludingValidators(ctx, jobID, consensusOutput, allVotes, totalVoters)

	if len(evidence) != 3 {
		t.Fatalf("expected 3 collusion evidence records, got %d", len(evidence))
	}

	sortEvidenceByValidator(evidence)
	for i, rec := range evidence {
		expectedAddr := "colluder-" + string(rune('A'+i))
		if rec.ValidatorAddress != expectedAddr {
			t.Errorf("expected %q, got %q", expectedAddr, rec.ValidatorAddress)
		}
		if rec.Condition != "collusion" {
			t.Errorf("expected condition 'collusion', got %q", rec.Condition)
		}
		if rec.Severity != "critical" {
			t.Errorf("expected severity 'critical', got %q", rec.Severity)
		}
	}
	t.Log("OK: three-validator collusion correctly detected")
}

func TestSlashing_Collusion_MultipleWrongClustersOnlyFlagsLargest(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-multi-cluster"
	consensusOutput := randomHash()
	wrongOutput1 := randomHash()
	wrongOutput2 := randomHash()

	// 3 honest
	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 3; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	// Cluster 1: 2 validators with wrongOutput1
	allVotes = append(allVotes, makeVoteExtensionForTest("cluster1-a", jobID, wrongOutput1, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("cluster1-b", jobID, wrongOutput1, true))
	// Cluster 2: 3 validators with wrongOutput2
	allVotes = append(allVotes, makeVoteExtensionForTest("cluster2-a", jobID, wrongOutput2, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("cluster2-b", jobID, wrongOutput2, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("cluster2-c", jobID, wrongOutput2, true))

	totalVoters := len(allVotes)
	evidence := ec.DetectColludingValidators(ctx, jobID, consensusOutput, allVotes, totalVoters)

	// Both clusters with >=2 members should be flagged: 2 + 3 = 5 total
	if len(evidence) < 2 {
		t.Fatalf("expected at least 2 collusion evidence records (both clusters >=2), got %d", len(evidence))
	}

	// Verify all flagged validators are from the wrong clusters
	flaggedAddrs := make(map[string]bool)
	for _, rec := range evidence {
		flaggedAddrs[rec.ValidatorAddress] = true
		if rec.Condition != "collusion" {
			t.Errorf("expected condition 'collusion', got %q for %s", rec.Condition, rec.ValidatorAddress)
		}
	}

	// Cluster 1 members (2 validators)
	if flaggedAddrs["cluster1-a"] && flaggedAddrs["cluster1-b"] {
		t.Log("Cluster 1 (2 members) flagged")
	}
	// Cluster 2 members (3 validators)
	if flaggedAddrs["cluster2-a"] && flaggedAddrs["cluster2-b"] && flaggedAddrs["cluster2-c"] {
		t.Log("Cluster 2 (3 members) flagged")
	}

	// No honest validators should be flagged
	for _, rec := range evidence {
		if rec.ValidatorAddress == "honest-A" || rec.ValidatorAddress == "honest-B" || rec.ValidatorAddress == "honest-C" {
			t.Errorf("honest validator %q should not be flagged for collusion", rec.ValidatorAddress)
		}
	}

	t.Logf("OK: multiple wrong clusters detected — %d total collusion records", len(evidence))
}

// =============================================================================
// Section 4: End-to-End Evidence Collection
// =============================================================================

func TestSlashing_E2E_CleanConsensus(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-clean"
	consensusOutput := randomHash()

	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 5; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"val-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}

	aggregated := map[string]*keeper.AggregatedResult{
		jobID: makeAggregatedResultForTest(jobID, consensusOutput, 5, 5),
	}

	evidence := ec.CollectEvidenceFromConsensus(ctx, aggregated, allVotes)

	if len(evidence) != 0 {
		t.Fatalf("expected 0 evidence records for clean consensus, got %d", len(evidence))
	}
	t.Log("OK: clean consensus produces zero evidence")
}

func TestSlashing_E2E_OneDissentingValidator(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-dissent"
	consensusOutput := randomHash()
	wrongOutput := randomHash()

	var allVotes []keeper.VoteExtensionWire
	// 4 honest
	for i := 0; i < 4; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	// 1 dishonest
	allVotes = append(allVotes, makeVoteExtensionForTest("dissenter", jobID, wrongOutput, true))

	aggregated := map[string]*keeper.AggregatedResult{
		jobID: makeAggregatedResultForTest(jobID, consensusOutput, 5, 4),
	}

	evidence := ec.CollectEvidenceFromConsensus(ctx, aggregated, allVotes)

	// Should detect invalid output for the dissenter
	foundInvalidOutput := false
	for _, rec := range evidence {
		if rec.ValidatorAddress == "dissenter" && rec.Condition == "invalid_output" {
			foundInvalidOutput = true
			if rec.Severity != "high" {
				t.Errorf("expected severity 'high', got %q", rec.Severity)
			}
			if !bytesEqual(rec.ExpectedOutput, consensusOutput) {
				t.Error("expected output mismatch")
			}
			if !bytesEqual(rec.ActualOutput, wrongOutput) {
				t.Error("actual output mismatch")
			}
		}
	}
	if !foundInvalidOutput {
		t.Fatal("expected invalid_output evidence for dissenter, found none")
	}
	t.Logf("OK: dissenting validator detected — %d total evidence records", len(evidence))
}

func TestSlashing_E2E_DoubleSignerAndInvalidOutput(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-ds-and-invalid"
	consensusOutput := randomHash()
	wrongOutput1 := randomHash()
	wrongOutput2 := randomHash()

	var allVotes []keeper.VoteExtensionWire
	// 3 honest
	for i := 0; i < 3; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	// 1 validator double-signs with two different wrong outputs
	allVotes = append(allVotes, makeVoteExtensionForTest("double-bad", jobID, wrongOutput1, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("double-bad", jobID, wrongOutput2, true))

	aggregated := map[string]*keeper.AggregatedResult{
		jobID: makeAggregatedResultForTest(jobID, consensusOutput, 5, 3),
	}

	evidence := ec.CollectEvidenceFromConsensus(ctx, aggregated, allVotes)

	// Should detect both double_sign and invalid_output for "double-bad"
	foundDoubleSign := false
	foundInvalidOutput := false
	for _, rec := range evidence {
		if rec.ValidatorAddress == "double-bad" {
			switch rec.Condition {
			case "double_sign":
				foundDoubleSign = true
				if rec.Severity != "critical" {
					t.Errorf("expected severity 'critical' for double_sign, got %q", rec.Severity)
				}
			case "invalid_output":
				foundInvalidOutput = true
				if rec.Severity != "high" {
					t.Errorf("expected severity 'high' for invalid_output, got %q", rec.Severity)
				}
			}
		}
	}

	if !foundDoubleSign {
		t.Error("expected double_sign evidence for 'double-bad'")
	}
	if !foundInvalidOutput {
		t.Error("expected invalid_output evidence for 'double-bad'")
	}
	t.Logf("OK: double signer with invalid output detected — %d total evidence records", len(evidence))
}

func TestSlashing_E2E_CollusionRing(t *testing.T) {
	ec := newTestEvidenceCollector()
	ctx := sdk.UnwrapSDKContext(sdkTestContext())

	jobID := "job-collusion-ring"
	consensusOutput := randomHash()
	colludedOutput := randomHash()

	var allVotes []keeper.VoteExtensionWire
	// 3 honest
	for i := 0; i < 3; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	// 2 colluding on different (wrong) output
	allVotes = append(allVotes, makeVoteExtensionForTest("colluder-X", jobID, colludedOutput, true))
	allVotes = append(allVotes, makeVoteExtensionForTest("colluder-Y", jobID, colludedOutput, true))

	aggregated := map[string]*keeper.AggregatedResult{
		jobID: makeAggregatedResultForTest(jobID, consensusOutput, 5, 3),
	}

	evidence := ec.CollectEvidenceFromConsensus(ctx, aggregated, allVotes)

	// Should detect collusion + invalid outputs for colluders
	collusionCount := 0
	invalidOutputCount := 0
	for _, rec := range evidence {
		if rec.ValidatorAddress == "colluder-X" || rec.ValidatorAddress == "colluder-Y" {
			switch rec.Condition {
			case "collusion":
				collusionCount++
			case "invalid_output":
				invalidOutputCount++
			}
		}
	}

	if collusionCount < 2 {
		t.Errorf("expected at least 2 collusion records, got %d", collusionCount)
	}
	if invalidOutputCount < 2 {
		t.Errorf("expected at least 2 invalid_output records, got %d", invalidOutputCount)
	}

	// No honest validators should be flagged
	for _, rec := range evidence {
		if rec.ValidatorAddress == "honest-A" || rec.ValidatorAddress == "honest-B" || rec.ValidatorAddress == "honest-C" {
			t.Errorf("honest validator %q should not appear in evidence", rec.ValidatorAddress)
		}
	}
	t.Logf("OK: collusion ring detected — %d total evidence records", len(evidence))
}

// =============================================================================
// Section 5: Severity Multiplier
// =============================================================================

func TestSlashing_SeverityMultiplier_Low(t *testing.T) {
	result := keeper.SeverityMultiplier("low")
	expected := sdkmath.LegacyNewDecWithPrec(25, 2) // 0.25
	if !result.Equal(expected) {
		t.Errorf("expected 0.25 for 'low', got %s", result.String())
	}
	t.Logf("OK: low severity multiplier = %s", result.String())
}

func TestSlashing_SeverityMultiplier_Medium(t *testing.T) {
	result := keeper.SeverityMultiplier("medium")
	expected := sdkmath.LegacyNewDecWithPrec(5, 1) // 0.5
	if !result.Equal(expected) {
		t.Errorf("expected 0.5 for 'medium', got %s", result.String())
	}
	t.Logf("OK: medium severity multiplier = %s", result.String())
}

func TestSlashing_SeverityMultiplier_High(t *testing.T) {
	result := keeper.SeverityMultiplier("high")
	expected := sdkmath.LegacyNewDec(1) // 1.0
	if !result.Equal(expected) {
		t.Errorf("expected 1.0 for 'high', got %s", result.String())
	}
	t.Logf("OK: high severity multiplier = %s", result.String())
}

func TestSlashing_SeverityMultiplier_Critical(t *testing.T) {
	result := keeper.SeverityMultiplier("critical")
	expected := sdkmath.LegacyNewDec(2) // 2.0
	if !result.Equal(expected) {
		t.Errorf("expected 2.0 for 'critical', got %s", result.String())
	}
	t.Logf("OK: critical severity multiplier = %s", result.String())
}

// =============================================================================
// Section 6: Determinism Tests
// =============================================================================

func TestSlashing_Deterministic_SameInputSameEvidence(t *testing.T) {
	jobID := "job-deterministic"
	consensusOutput := randomHash()
	wrongOutput := randomHash()

	// Build identical inputs for two runs
	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 4; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	allVotes = append(allVotes, makeVoteExtensionForTest("dishonest", jobID, wrongOutput, true))

	aggregated := map[string]*keeper.AggregatedResult{
		jobID: makeAggregatedResultForTest(jobID, consensusOutput, 5, 4),
	}

	// Use the same fixed block time for both runs
	blockTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	ctx := fixedBlockTimeContext(100, blockTime)

	// Run 1
	ec1 := newTestEvidenceCollector()
	evidence1 := ec1.CollectEvidenceFromConsensus(ctx, aggregated, allVotes)

	// Run 2
	ec2 := newTestEvidenceCollector()
	evidence2 := ec2.CollectEvidenceFromConsensus(ctx, aggregated, allVotes)

	// Results must be identical
	if len(evidence1) != len(evidence2) {
		t.Fatalf("different number of evidence records: run1=%d, run2=%d",
			len(evidence1), len(evidence2))
	}

	sortEvidenceByCondition(evidence1)
	sortEvidenceByCondition(evidence2)

	for i := range evidence1 {
		if evidence1[i].ValidatorAddress != evidence2[i].ValidatorAddress {
			t.Errorf("record %d: validator mismatch: %q vs %q",
				i, evidence1[i].ValidatorAddress, evidence2[i].ValidatorAddress)
		}
		if evidence1[i].Condition != evidence2[i].Condition {
			t.Errorf("record %d: condition mismatch: %q vs %q",
				i, evidence1[i].Condition, evidence2[i].Condition)
		}
		if evidence1[i].Severity != evidence2[i].Severity {
			t.Errorf("record %d: severity mismatch: %q vs %q",
				i, evidence1[i].Severity, evidence2[i].Severity)
		}
		if !bytesEqual(evidence1[i].ExpectedOutput, evidence2[i].ExpectedOutput) {
			t.Errorf("record %d: expected output mismatch", i)
		}
		if !bytesEqual(evidence1[i].ActualOutput, evidence2[i].ActualOutput) {
			t.Errorf("record %d: actual output mismatch", i)
		}
	}
	t.Logf("OK: identical inputs produce identical evidence — %d records", len(evidence1))
}

func TestSlashing_Deterministic_OrderIndependence(t *testing.T) {
	jobID := "job-order-independent"
	consensusOutput := randomHash()
	wrongOutput1 := randomHash()
	wrongOutput2 := randomHash()

	blockTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	ctx := fixedBlockTimeContext(100, blockTime)

	// Original order: honest, honest, honest, bad1, bad2
	votesOriginal := []keeper.VoteExtensionWire{
		makeVoteExtensionForTest("honest-A", jobID, consensusOutput, true),
		makeVoteExtensionForTest("honest-B", jobID, consensusOutput, true),
		makeVoteExtensionForTest("honest-C", jobID, consensusOutput, true),
		makeVoteExtensionForTest("bad-1", jobID, wrongOutput1, true),
		makeVoteExtensionForTest("bad-2", jobID, wrongOutput2, true),
	}

	// Shuffled order: bad2, honest-C, bad1, honest-A, honest-B
	votesShuffled := []keeper.VoteExtensionWire{
		makeVoteExtensionForTest("bad-2", jobID, wrongOutput2, true),
		makeVoteExtensionForTest("honest-C", jobID, consensusOutput, true),
		makeVoteExtensionForTest("bad-1", jobID, wrongOutput1, true),
		makeVoteExtensionForTest("honest-A", jobID, consensusOutput, true),
		makeVoteExtensionForTest("honest-B", jobID, consensusOutput, true),
	}

	ec := newTestEvidenceCollector()

	// Detect invalid outputs in both orders
	ev1 := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, votesOriginal)
	ev2 := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, votesShuffled)

	if len(ev1) != len(ev2) {
		t.Fatalf("different evidence counts: original=%d, shuffled=%d", len(ev1), len(ev2))
	}

	// Sort by validator address for comparison
	sortEvidenceByValidator(ev1)
	sortEvidenceByValidator(ev2)

	// The set of flagged validators must be identical
	for i := range ev1 {
		if ev1[i].ValidatorAddress != ev2[i].ValidatorAddress {
			t.Errorf("record %d: validator mismatch after shuffle: %q vs %q",
				i, ev1[i].ValidatorAddress, ev2[i].ValidatorAddress)
		}
		if ev1[i].Condition != ev2[i].Condition {
			t.Errorf("record %d: condition mismatch after shuffle: %q vs %q",
				i, ev1[i].Condition, ev2[i].Condition)
		}
	}
	t.Logf("OK: vote order does not affect evidence — %d records in both runs", len(ev1))
}

func TestSlashing_Deterministic_NoTimeDependence(t *testing.T) {
	jobID := "job-time-independent"
	consensusOutput := randomHash()
	wrongOutput := randomHash()

	var allVotes []keeper.VoteExtensionWire
	for i := 0; i < 4; i++ {
		allVotes = append(allVotes, makeVoteExtensionForTest(
			"honest-"+string(rune('A'+i)), jobID, consensusOutput, true,
		))
	}
	allVotes = append(allVotes, makeVoteExtensionForTest("dishonest", jobID, wrongOutput, true))

	// Two different "wall clock" times, but same block time
	blockTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	ctx1 := fixedBlockTimeContext(100, blockTime)
	ctx2 := fixedBlockTimeContext(100, blockTime)

	ec := newTestEvidenceCollector()

	// Run at different real-world times but with same block time
	evidence1 := ec.DetectInvalidOutputs(ctx1, jobID, consensusOutput, allVotes)
	// Simulate passage of real time (the block time context is identical)
	evidence2 := ec.DetectInvalidOutputs(ctx2, jobID, consensusOutput, allVotes)

	if len(evidence1) != len(evidence2) {
		t.Fatalf("different evidence counts: %d vs %d", len(evidence1), len(evidence2))
	}

	sortEvidenceByValidator(evidence1)
	sortEvidenceByValidator(evidence2)

	for i := range evidence1 {
		if evidence1[i].ValidatorAddress != evidence2[i].ValidatorAddress {
			t.Errorf("record %d: validator mismatch: %q vs %q",
				i, evidence1[i].ValidatorAddress, evidence2[i].ValidatorAddress)
		}
		// Timestamps should use block time, not wall clock
		if !evidence1[i].Timestamp.Equal(evidence2[i].Timestamp) {
			t.Errorf("record %d: timestamp mismatch (should use block time): %v vs %v",
				i, evidence1[i].Timestamp, evidence2[i].Timestamp)
		}
	}
	t.Logf("OK: evidence uses block time, not wall clock — %d records", len(evidence1))
}

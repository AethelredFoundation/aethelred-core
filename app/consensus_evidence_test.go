package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

func TestParseInjectedConsensusTx_RejectsNegativeValues(t *testing.T) {
	raw := map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          "job-neg",
		"output_hash":     make32Bytes(),
		"validator_count": -1,
		"total_votes":     1,
		"agreement_power": 1,
		"total_power":     1,
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}

	_, err = parseInjectedConsensusTx(data)
	if err == nil || !strings.Contains(err.Error(), "negative consensus evidence values") {
		t.Fatalf("expected negative evidence rejection, got %v", err)
	}
}

func TestValidateConsensusEvidenceThreshold_NoFallbackMissingPower(t *testing.T) {
	err := validateConsensusEvidenceThreshold(
		1, 1,
		1, 0,
		67,
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "missing total voting power") {
		t.Fatalf("expected missing power error, got %v", err)
	}
}

func TestValidateConsensusEvidenceThreshold_VoteFallback(t *testing.T) {
	// For threshold 67 and total votes 3, required votes are 3.
	if err := validateConsensusEvidenceThreshold(3, 3, 0, 0, 67, true); err != nil {
		t.Fatalf("expected fallback vote threshold pass, got %v", err)
	}

	err := validateConsensusEvidenceThreshold(2, 3, 0, 0, 67, true)
	if err == nil || !strings.Contains(err.Error(), "insufficient validator consensus") {
		t.Fatalf("expected fallback vote threshold failure, got %v", err)
	}
}

func TestRequiredConsensusPower(t *testing.T) {
	if got := requiredConsensusPower(0, 67); got != 0 {
		t.Fatalf("expected zero for non-positive power, got %d", got)
	}
	// Threshold must clamp to 67 in BFT-safe mode.
	if got := requiredConsensusPower(100, 50); got != 68 {
		t.Fatalf("expected clamped threshold result 68, got %d", got)
	}
}

func TestParseInjectedConsensusTx_InvalidJSON(t *testing.T) {
	_, err := parseInjectedConsensusTx([]byte(`{"type":`))
	if err == nil || !strings.Contains(err.Error(), "failed to unmarshal injected consensus tx") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestValidateInjectedConsensusTxFormat_Errors(t *testing.T) {
	cases := []struct {
		name string
		tx   *InjectedVoteExtensionTx
		want string
	}{
		{name: "nil", tx: nil, want: "nil injected consensus tx"},
		{
			name: "wrong type",
			tx:   &InjectedVoteExtensionTx{Type: "other", JobID: "job", OutputHash: make32Bytes()},
			want: "unexpected injected tx type",
		},
		{
			name: "missing job",
			tx:   &InjectedVoteExtensionTx{Type: "create_seal_from_consensus", OutputHash: make32Bytes()},
			want: "missing job ID",
		},
		{
			name: "bad output",
			tx:   &InjectedVoteExtensionTx{Type: "create_seal_from_consensus", JobID: "job", OutputHash: []byte{1}},
			want: "invalid output hash length",
		},
		{
			name: "validator greater than votes",
			tx: &InjectedVoteExtensionTx{
				Type:           "create_seal_from_consensus",
				JobID:          "job",
				OutputHash:     make32Bytes(),
				ValidatorCount: 2,
				TotalVotes:     1,
			},
			want: "validator count exceeds total votes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInjectedConsensusTxFormat(tc.tx)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateConsensusEvidenceThreshold_PowerPath(t *testing.T) {
	if err := validateConsensusEvidenceThreshold(0, 0, 7, 10, 67, false); err != nil {
		t.Fatalf("expected power path success, got %v", err)
	}
	err := validateConsensusEvidenceThreshold(0, 0, 6, 10, 67, false)
	if err == nil || !strings.Contains(err.Error(), "insufficient validator power consensus") {
		t.Fatalf("expected insufficient power error, got %v", err)
	}
}

func TestAuditProposalConsensusEvidence_OK(t *testing.T) {
	commit := testCommitInfo(1)
	tx := mustMarshalInjected(t, "job-audit-ok", make32Bytes(), 2, 2, 2, 2)

	audit := AuditProposalConsensusEvidence([][]byte{tx}, commit, 67)
	if !audit.Passed() {
		t.Fatalf("expected audit to pass, got %s", audit.Error())
	}
}

func TestAuditProposalConsensusEvidence_DetectsDuplicateJobID(t *testing.T) {
	commit := testCommitInfo(1)
	tx1 := mustMarshalInjected(t, "job-audit-dup", make32Bytes(), 2, 2, 2, 2)
	tx2 := mustMarshalInjected(t, "job-audit-dup", make32Bytes(), 2, 2, 2, 2)

	audit := AuditProposalConsensusEvidence([][]byte{tx1, tx2}, commit, 67)
	if audit.Passed() {
		t.Fatalf("expected audit to fail for duplicate job ID")
	}
	if !strings.Contains(audit.Error(), "duplicate_job_consensus_tx") {
		t.Fatalf("expected duplicate job ID issue, got %s", audit.Error())
	}
}

func TestAuditProposalConsensusEvidence_DetectsInvalidInjectedTx(t *testing.T) {
	commit := testCommitInfo(1)
	invalid := []byte(`{"type":"create_seal_from_consensus","job_id":"job-bad"}`)

	audit := AuditProposalConsensusEvidence([][]byte{invalid}, commit, 67)
	if audit.Passed() {
		t.Fatalf("expected audit to fail for invalid injected tx")
	}
	if !strings.Contains(audit.Error(), "invalid_injected_tx") {
		t.Fatalf("expected invalid tx issue, got %s", audit.Error())
	}
}

func TestAuditProposalConsensusEvidence_IgnoresNonInjectedTx(t *testing.T) {
	commit := testCommitInfo(1)
	audit := AuditProposalConsensusEvidence([][]byte{[]byte("not-json-tx")}, commit, 67)
	if !audit.Passed() {
		t.Fatalf("expected non-injected tx to be ignored, got %s", audit.Error())
	}
	if audit.InjectedTxCount != 0 {
		t.Fatalf("expected injected tx count 0, got %d", audit.InjectedTxCount)
	}
}

func TestValidateInjectedConsensusEvidenceAgainstCommit_VotesMismatch(t *testing.T) {
	tx := mustMarshalInjected(t, "job-commit-bad-votes", make32Bytes(), 1, 1, 2, 2)
	commit := testCommitInfo(1)

	err := validateInjectedConsensusEvidenceAgainstCommit(tx, commit, 67)
	if err == nil || !strings.Contains(err.Error(), "total votes mismatch") {
		t.Fatalf("expected total votes mismatch error, got %v", err)
	}
}

func TestValidateInjectedConsensusEvidenceAgainstCommit_ZeroPowerRejected(t *testing.T) {
	tx := mustMarshalInjected(t, "job-commit-zero-power", make32Bytes(), 0, 0, 0, 0)
	commit := abci.CommitInfo{}

	err := validateInjectedConsensusEvidenceAgainstCommit(tx, commit, 67)
	if err == nil || !strings.Contains(err.Error(), "below threshold") {
		t.Fatalf("expected below threshold error, got %v", err)
	}
}

func TestValidateInjectedConsensusEvidenceAgainstCommit_InvalidTxBytes(t *testing.T) {
	commit := testCommitInfo(1)
	err := validateInjectedConsensusEvidenceAgainstCommit([]byte("{"), commit, 67)
	if err == nil || !strings.Contains(err.Error(), "failed to unmarshal injected consensus tx") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestProposalConsensusAuditError_TruncatesIssues(t *testing.T) {
	audit := ProposalConsensusAudit{}
	for i := 0; i < 4; i++ {
		audit.addIssue(i, fmt.Sprintf("job-%d", i), "code", "detail")
	}
	err := audit.Error()
	if !strings.Contains(err, "and 1 more") {
		t.Fatalf("expected truncated issue summary, got %s", err)
	}
}

func TestProposalConsensusAuditError_NoIssues(t *testing.T) {
	audit := ProposalConsensusAudit{}
	if got := audit.Error(); got != "" {
		t.Fatalf("expected empty error string, got %q", got)
	}
	if !audit.Passed() {
		t.Fatalf("expected passed audit with no issues")
	}
}

func testCommitInfo(power int64) abci.CommitInfo {
	return abci.CommitInfo{
		Votes: []abci.VoteInfo{
			{
				Validator:   abci.Validator{Address: []byte("validator-1"), Power: power},
				BlockIdFlag: cmtproto.BlockIDFlagCommit,
			},
			{
				Validator:   abci.Validator{Address: []byte("validator-2"), Power: power},
				BlockIdFlag: cmtproto.BlockIDFlagCommit,
			},
		},
	}
}

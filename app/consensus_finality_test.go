package app

import (
	"encoding/json"
	"strings"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestValidateComputationFinality_MissingInjectedTx(t *testing.T) {
	app := &AethelredApp{}
	output := make32Bytes()

	results := map[string]*pouwkeeper.AggregatedResult{
		"job-missing": {
			JobID:          "job-missing",
			OutputHash:     output,
			TotalVotes:     10,
			AgreementCount: 7,
			TotalPower:     10,
			AgreementPower: 7,
			HasConsensus:   true,
		},
	}

	err := app.validateComputationFinality(results, nil, 67)
	if err == nil || !strings.Contains(err.Error(), "missing injected consensus tx") {
		t.Fatalf("expected missing injected tx error, got %v", err)
	}
}

func TestValidateComputationFinality_ExtraInjectedTxWithoutConsensus(t *testing.T) {
	app := &AethelredApp{}
	output := make32Bytes()

	results := map[string]*pouwkeeper.AggregatedResult{
		"job-no-quorum": {
			JobID:        "job-no-quorum",
			OutputHash:   output,
			HasConsensus: false,
		},
	}

	txs := [][]byte{mustMarshalInjected(t, "job-no-quorum", output, 1, 1, 1, 1)}
	err := app.validateComputationFinality(results, txs, 67)
	if err == nil || !strings.Contains(err.Error(), "injected consensus tx without quorum") {
		t.Fatalf("expected injected without quorum error, got %v", err)
	}
}

func TestValidateComputationFinality_OutputHashMismatch(t *testing.T) {
	app := &AethelredApp{}
	output := make32Bytes()
	other := make32Bytes()
	other[0] ^= 0xFF

	results := map[string]*pouwkeeper.AggregatedResult{
		"job-mismatch": {
			JobID:          "job-mismatch",
			OutputHash:     output,
			TotalVotes:     10,
			AgreementCount: 7,
			TotalPower:     10,
			AgreementPower: 7,
			HasConsensus:   true,
		},
	}

	txs := [][]byte{mustMarshalInjected(t, "job-mismatch", other, 7, 10, 7, 10)}
	err := app.validateComputationFinality(results, txs, 67)
	if err == nil || !strings.Contains(err.Error(), "output hash mismatch") {
		t.Fatalf("expected output hash mismatch error, got %v", err)
	}
}

func TestValidateComputationFinality_OK(t *testing.T) {
	app := &AethelredApp{}
	output := make32Bytes()

	results := map[string]*pouwkeeper.AggregatedResult{
		"job-ok": {
			JobID:          "job-ok",
			OutputHash:     output,
			TotalVotes:     10,
			AgreementCount: 7,
			TotalPower:     10,
			AgreementPower: 7,
			HasConsensus:   true,
		},
	}

	txs := [][]byte{mustMarshalInjected(t, "job-ok", output, 7, 10, 7, 10)}
	if err := app.validateComputationFinality(results, txs, 67); err != nil {
		t.Fatalf("expected finality to pass, got %v", err)
	}
}

func TestValidateComputationFinality_InjectedPowerMismatch(t *testing.T) {
	app := &AethelredApp{}
	output := make32Bytes()

	results := map[string]*pouwkeeper.AggregatedResult{
		"job-mismatch-power": {
			JobID:          "job-mismatch-power",
			OutputHash:     output,
			TotalVotes:     10,
			AgreementCount: 7,
			TotalPower:     10,
			AgreementPower: 7,
			HasConsensus:   true,
		},
	}

	// Self-consistent for total_power=5 but does not match the recomputed
	// aggregate evidence (total_power=10), so it must be rejected.
	txs := [][]byte{mustMarshalInjected(t, "job-mismatch-power", output, 4, 5, 4, 5)}
	err := app.validateComputationFinality(results, txs, 67)
	if err == nil || !strings.Contains(err.Error(), "power mismatch") {
		t.Fatalf("expected injected consensus power mismatch error, got %v", err)
	}
}

func TestValidateInjectedConsensusEvidenceAgainstCommit_OK(t *testing.T) {
	tx := mustMarshalInjected(t, "job-commit-ok", make32Bytes(), 2, 2, 2, 2)
	commit := abci.CommitInfo{
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: []byte("val1"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: []byte("val2"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	if err := validateInjectedConsensusEvidenceAgainstCommit(tx, commit, 67); err != nil {
		t.Fatalf("expected commit-evidence validation to pass, got %v", err)
	}
}

func TestValidateInjectedConsensusEvidenceAgainstCommit_TotalPowerMismatch(t *testing.T) {
	tx := mustMarshalInjected(t, "job-commit-bad-power", make32Bytes(), 2, 2, 2, 3)
	commit := abci.CommitInfo{
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: []byte("val1"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: []byte("val2"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	err := validateInjectedConsensusEvidenceAgainstCommit(tx, commit, 67)
	if err == nil || !strings.Contains(err.Error(), "total power mismatch") {
		t.Fatalf("expected total power mismatch error, got %v", err)
	}
}

func TestValidateInjectedConsensusEvidenceAgainstCommit_BelowThreshold(t *testing.T) {
	tx := mustMarshalInjected(t, "job-commit-bad-threshold", make32Bytes(), 1, 2, 1, 2)
	commit := abci.CommitInfo{
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: []byte("val1"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: []byte("val2"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	err := validateInjectedConsensusEvidenceAgainstCommit(tx, commit, 67)
	if err == nil || !strings.Contains(err.Error(), "below threshold") {
		t.Fatalf("expected threshold error, got %v", err)
	}
}

func mustMarshalInjected(t *testing.T, jobID string, output []byte, validatorCount, totalVotes int, agreementPower, totalPower int64) []byte {
	t.Helper()
	tx := map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          jobID,
		"output_hash":     output,
		"validator_count": validatorCount,
		"total_votes":     totalVotes,
		"agreement_power": agreementPower,
		"total_power":     totalPower,
	}
	data, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal injected tx: %v", err)
	}
	return data
}

func make32Bytes() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i + 1)
	}
	return out
}

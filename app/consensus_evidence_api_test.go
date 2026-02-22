package app

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

func TestRunConsensusEvidenceAudit_ObjectTxPayload(t *testing.T) {
	req := ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 67,
		ProposedLastCommit: testConsensusAuditCommit(),
		Txs: []json.RawMessage{
			mustMarshalRawJSON(t, map[string]interface{}{
				"type":            "create_seal_from_consensus",
				"job_id":          "job-api-object",
				"output_hash":     make32Bytes(),
				"validator_count": 2,
				"total_votes":     2,
				"agreement_power": 2,
				"total_power":     2,
			}),
		},
	}

	resp, err := RunConsensusEvidenceAudit(req)
	if err != nil {
		t.Fatalf("audit execution failed: %v", err)
	}
	if !resp.Passed {
		t.Fatalf("expected audit pass, got %+v", resp)
	}
	if resp.ConsensusThreshold != 67 {
		t.Fatalf("expected threshold=67, got %d", resp.ConsensusThreshold)
	}
}

func TestRunConsensusEvidenceAudit_Base64TxPayload(t *testing.T) {
	txBytes := mustMarshalRawJSON(t, map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          "job-api-base64",
		"output_hash":     make32Bytes(),
		"validator_count": 2,
		"total_votes":     2,
		"agreement_power": 2,
		"total_power":     2,
	})

	encoded := base64.StdEncoding.EncodeToString(txBytes)
	raw, err := json.Marshal(encoded)
	if err != nil {
		t.Fatalf("marshal encoded tx: %v", err)
	}

	req := ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 67,
		ProposedLastCommit: testConsensusAuditCommit(),
		Txs:                []json.RawMessage{raw},
	}

	resp, err := RunConsensusEvidenceAudit(req)
	if err != nil {
		t.Fatalf("audit execution failed: %v", err)
	}
	if !resp.Passed {
		t.Fatalf("expected audit pass, got %+v", resp)
	}
}

func TestRunConsensusEvidenceAudit_InvalidStringPayload(t *testing.T) {
	raw, err := json.Marshal("%%%")
	if err != nil {
		t.Fatalf("marshal raw tx string: %v", err)
	}

	req := ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 67,
		ProposedLastCommit: testConsensusAuditCommit(),
		Txs:                []json.RawMessage{raw},
	}

	_, err = RunConsensusEvidenceAudit(req)
	if err == nil || !strings.Contains(err.Error(), "invalid tx payload") {
		t.Fatalf("expected invalid tx payload error, got %v", err)
	}
}

func TestRunConsensusEvidenceAudit_HexTxPayload(t *testing.T) {
	txBytes := mustMarshalRawJSON(t, map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          "job-api-hex",
		"output_hash":     make32Bytes(),
		"validator_count": 2,
		"total_votes":     2,
		"agreement_power": 2,
		"total_power":     2,
	})
	hexTx := "0x" + hex.EncodeToString(txBytes)
	raw, err := json.Marshal(hexTx)
	if err != nil {
		t.Fatalf("marshal hex tx: %v", err)
	}

	resp, err := RunConsensusEvidenceAudit(ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 67,
		ProposedLastCommit: testConsensusAuditCommit(),
		Txs:                []json.RawMessage{raw},
	})
	if err != nil {
		t.Fatalf("audit execution failed: %v", err)
	}
	if !resp.Passed {
		t.Fatalf("expected audit pass, got %+v", resp)
	}
}

func TestRunConsensusEvidenceAudit_RawJSONStringPayload(t *testing.T) {
	tx := mustMarshalRawJSON(t, map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          "job-api-raw-json",
		"output_hash":     make32Bytes(),
		"validator_count": 2,
		"total_votes":     2,
		"agreement_power": 2,
		"total_power":     2,
	})

	resp, err := RunConsensusEvidenceAudit(ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 67,
		ProposedLastCommit: testConsensusAuditCommit(),
		Txs:                []json.RawMessage{tx},
	})
	if err != nil {
		t.Fatalf("audit execution failed: %v", err)
	}
	if !resp.Passed {
		t.Fatalf("expected audit pass, got %+v", resp)
	}
}

func TestDecodeAuditTx_EmptyPayload(t *testing.T) {
	_, err := decodeAuditTx(json.RawMessage("   "))
	if err == nil || !strings.Contains(err.Error(), "empty tx payload") {
		t.Fatalf("expected empty payload error, got %v", err)
	}
}

func TestDecodeAuditTxString_Empty(t *testing.T) {
	_, err := decodeAuditTxString(" ")
	if err == nil || !strings.Contains(err.Error(), "empty tx string") {
		t.Fatalf("expected empty tx string error, got %v", err)
	}
}

func TestRunConsensusEvidenceAudit_ThresholdNormalized(t *testing.T) {
	req := ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 60,
		ProposedLastCommit: testConsensusAuditCommit(),
	}

	resp, err := RunConsensusEvidenceAudit(req)
	if err != nil {
		t.Fatalf("audit execution failed: %v", err)
	}
	if resp.ConsensusThreshold != 67 {
		t.Fatalf("expected threshold normalization to 67, got %d", resp.ConsensusThreshold)
	}
}

func TestRunConsensusEvidenceAudit_SetsErrorForFailedAudit(t *testing.T) {
	req := ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 67,
		ProposedLastCommit: testConsensusAuditCommit(),
		Txs: []json.RawMessage{
			mustMarshalRawJSON(t, map[string]interface{}{
				"type":            "create_seal_from_consensus",
				"job_id":          "job-api-fail",
				"output_hash":     make32Bytes(),
				"validator_count": 1,
				"total_votes":     1, // commit has 2 votes -> mismatch
				"agreement_power": 2,
				"total_power":     2,
			}),
		},
	}

	resp, err := RunConsensusEvidenceAudit(req)
	if err != nil {
		t.Fatalf("audit execution failed: %v", err)
	}
	if resp.Passed {
		t.Fatalf("expected failed audit response")
	}
	if resp.Error == "" {
		t.Fatalf("expected error summary in failed response")
	}
}

func TestDecodeAuditTx_InvalidQuotedStringJSON(t *testing.T) {
	_, err := decodeAuditTx(json.RawMessage(`"unterminated`))
	if err == nil || !strings.Contains(err.Error(), "invalid tx string encoding") {
		t.Fatalf("expected invalid tx string encoding, got %v", err)
	}
}

func TestDecodeAuditTxString_InvalidHex(t *testing.T) {
	_, err := decodeAuditTxString("0xzz")
	if err == nil || !strings.Contains(err.Error(), "invalid hex tx payload") {
		t.Fatalf("expected invalid hex payload error, got %v", err)
	}
}

func TestDecodeAuditTxString_JSONFallback(t *testing.T) {
	tx, err := decodeAuditTxString(`{"type":"create_seal_from_consensus"}`)
	if err != nil {
		t.Fatalf("expected JSON fallback success, got %v", err)
	}
	if !strings.Contains(string(tx), "create_seal_from_consensus") {
		t.Fatalf("expected raw JSON tx bytes, got %s", string(tx))
	}
}

func mustMarshalRawJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	bz, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal raw json: %v", err)
	}
	return json.RawMessage(bz)
}

func testConsensusAuditCommit() abci.CommitInfo {
	return abci.CommitInfo{
		Votes: []abci.VoteInfo{
			{
				Validator:   abci.Validator{Address: []byte("validator-1"), Power: 1},
				BlockIdFlag: cmtproto.BlockIDFlagCommit,
			},
			{
				Validator:   abci.Validator{Address: []byte("validator-2"), Power: 1},
				BlockIdFlag: cmtproto.BlockIDFlagCommit,
			},
		},
	}
}

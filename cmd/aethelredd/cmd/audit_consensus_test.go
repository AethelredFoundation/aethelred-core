package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

func TestAuditConsensusEvidenceCommand(t *testing.T) {
	req := map[string]interface{}{
		"consensus_threshold": 67,
		"proposed_last_commit": abci.CommitInfo{
			Votes: []abci.VoteInfo{
				{Validator: abci.Validator{Address: []byte("val1"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
				{Validator: abci.Validator{Address: []byte("val2"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			},
		},
		"txs": []map[string]interface{}{
			{
				"type":            "create_seal_from_consensus",
				"job_id":          "job-cli-ok",
				"output_hash":     makeCLI32Bytes(),
				"validator_count": 2,
				"total_votes":     2,
				"agreement_power": 2,
				"total_power":     2,
			},
		},
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(requestPath, payload, 0o600); err != nil {
		t.Fatalf("write request file: %v", err)
	}

	cmd := auditConsensusEvidenceCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--request-file", requestPath, "--pretty=false"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute command: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, `"passed":true`) {
		t.Fatalf("expected successful audit output, got %s", output)
	}
}

func makeCLI32Bytes() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i + 1)
	}
	return out
}

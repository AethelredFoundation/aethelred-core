package app

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	abci "github.com/cometbft/cometbft/abci/types"
)

// ConsensusEvidenceAuditRequest is the payload used by CLI/admin tooling to
// run the same consensus evidence checks used by ProcessProposal.
type ConsensusEvidenceAuditRequest struct {
	ConsensusThreshold int               `json:"consensus_threshold"`
	ProposedLastCommit abci.CommitInfo   `json:"proposed_last_commit"`
	Txs                []json.RawMessage `json:"txs"`
}

// ConsensusEvidenceAuditResponse captures the deterministic audit result.
type ConsensusEvidenceAuditResponse struct {
	Passed              bool                     `json:"passed"`
	Error               string                   `json:"error,omitempty"`
	ConsensusThreshold  int                      `json:"consensus_threshold"`
	RequiredCommitPower int64                    `json:"required_commit_power"`
	CommitTotalVotes    int                      `json:"commit_total_votes"`
	CommitTotalPower    int64                    `json:"commit_total_power"`
	TxCount             int                      `json:"tx_count"`
	InjectedTxCount     int                      `json:"injected_tx_count"`
	Issues              []ProposalConsensusIssue `json:"issues,omitempty"`
}

// RunConsensusEvidenceAudit executes the same injected consensus evidence
// validation used in ProcessProposal.
func RunConsensusEvidenceAudit(req ConsensusEvidenceAuditRequest) (ConsensusEvidenceAuditResponse, error) {
	threshold := normalizeConsensusThreshold(req.ConsensusThreshold)
	txs := make([][]byte, 0, len(req.Txs))
	for i := range req.Txs {
		tx, err := decodeAuditTx(req.Txs[i])
		if err != nil {
			return ConsensusEvidenceAuditResponse{}, fmt.Errorf("invalid tx payload at index %d: %w", i, err)
		}
		txs = append(txs, tx)
	}

	audit := AuditProposalConsensusEvidence(txs, req.ProposedLastCommit, threshold)
	resp := ConsensusEvidenceAuditResponse{
		Passed:              audit.Passed(),
		ConsensusThreshold:  threshold,
		RequiredCommitPower: requiredConsensusPower(audit.CommitTotalPower, threshold),
		CommitTotalVotes:    audit.CommitTotalVotes,
		CommitTotalPower:    audit.CommitTotalPower,
		TxCount:             len(txs),
		InjectedTxCount:     audit.InjectedTxCount,
		Issues:              append([]ProposalConsensusIssue(nil), audit.Issues...),
	}
	if !resp.Passed {
		resp.Error = audit.Error()
	}
	return resp, nil
}

func normalizeConsensusThreshold(threshold int) int {
	if threshold < 67 {
		return 67
	}
	return threshold
}

func decodeAuditTx(raw json.RawMessage) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("empty tx payload")
	}

	if strings.HasPrefix(trimmed, "\"") {
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, fmt.Errorf("invalid tx string encoding: %w", err)
		}
		return decodeAuditTxString(encoded)
	}

	return []byte(trimmed), nil
}

func decodeAuditTxString(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("empty tx string")
	}

	if strings.HasPrefix(encoded, "0x") || strings.HasPrefix(encoded, "0X") {
		bz, err := hex.DecodeString(encoded[2:])
		if err != nil {
			return nil, fmt.Errorf("invalid hex tx payload: %w", err)
		}
		return bz, nil
	}

	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, dec := range decoders {
		if bz, err := dec.DecodeString(encoded); err == nil {
			return bz, nil
		}
	}

	if json.Valid([]byte(encoded)) {
		return []byte(encoded), nil
	}
	return nil, fmt.Errorf("tx string payload must be base64/hex or JSON")
}

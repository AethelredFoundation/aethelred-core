package app

import (
	"fmt"
	"strings"

	abci "github.com/cometbft/cometbft/abci/types"
)

type ProposalConsensusIssue struct {
	TxIndex int
	JobID   string
	Code    string
	Detail  string
}

type ProposalConsensusAudit struct {
	ConsensusThreshold int
	CommitTotalVotes   int
	CommitTotalPower   int64
	InjectedTxCount    int
	Issues             []ProposalConsensusIssue
}

func (a ProposalConsensusAudit) Passed() bool {
	return len(a.Issues) == 0
}

func (a ProposalConsensusAudit) Error() string {
	if len(a.Issues) == 0 {
		return ""
	}
	max := len(a.Issues)
	if max > 3 {
		max = 3
	}
	parts := make([]string, 0, max)
	for i := 0; i < max; i++ {
		issue := a.Issues[i]
		base := fmt.Sprintf("tx[%d] %s", issue.TxIndex, issue.Code)
		if issue.JobID != "" {
			base += fmt.Sprintf(" job=%s", issue.JobID)
		}
		parts = append(parts, fmt.Sprintf("%s: %s", base, issue.Detail))
	}
	msg := strings.Join(parts, "; ")
	if len(a.Issues) > max {
		msg += fmt.Sprintf("; and %d more", len(a.Issues)-max)
	}
	return msg
}

func (a *ProposalConsensusAudit) addIssue(txIndex int, jobID, code, detail string) {
	a.Issues = append(a.Issues, ProposalConsensusIssue{
		TxIndex: txIndex,
		JobID:   jobID,
		Code:    code,
		Detail:  detail,
	})
}

func AuditProposalConsensusEvidence(txs [][]byte, commit abci.CommitInfo, consensusThreshold int) ProposalConsensusAudit {
	commitVotes, commitPower := commitVoteTotals(commit)
	audit := ProposalConsensusAudit{
		ConsensusThreshold: consensusThreshold,
		CommitTotalVotes:   commitVotes,
		CommitTotalPower:   commitPower,
	}

	seenJobs := make(map[string]int)
	for i, txBytes := range txs {
		if !IsInjectedVoteExtensionTx(txBytes) {
			continue
		}
		audit.InjectedTxCount++

		tx, err := parseInjectedConsensusTx(txBytes)
		if err != nil {
			audit.addIssue(i, "", "invalid_injected_tx", err.Error())
			continue
		}
		if firstIdx, exists := seenJobs[tx.JobID]; exists {
			audit.addIssue(i, tx.JobID, "duplicate_job_consensus_tx",
				fmt.Sprintf("duplicate injected consensus tx for job %s (first seen at tx[%d])", tx.JobID, firstIdx))
		} else {
			seenJobs[tx.JobID] = i
		}
		if err := validateInjectedConsensusEvidenceAgainstCommit(txBytes, commit, consensusThreshold); err != nil {
			audit.addIssue(i, tx.JobID, "commit_evidence_mismatch", err.Error())
		}
	}

	return audit
}

// requiredConsensusPower returns the minimum voting power required to satisfy
// the configured consensus threshold. The threshold is clamped to BFT-safe 67%.
func requiredConsensusPower(totalPower int64, consensusThreshold int) int64 {
	if consensusThreshold < 67 {
		consensusThreshold = 67
	}
	if totalPower <= 0 {
		return 0
	}
	return (totalPower*int64(consensusThreshold))/100 + 1
}

func parseInjectedConsensusTx(txBytes []byte) (*InjectedVoteExtensionTx, error) {
	tx, err := UnmarshalInjectedVoteExtensionTx(txBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal injected consensus tx: %w", err)
	}
	if err := validateInjectedConsensusTxFormat(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func validateInjectedConsensusTxFormat(tx *InjectedVoteExtensionTx) error {
	if tx == nil {
		return fmt.Errorf("nil injected consensus tx")
	}
	if tx.Type != "create_seal_from_consensus" {
		return fmt.Errorf("unexpected injected tx type: %s", tx.Type)
	}
	if tx.JobID == "" {
		return fmt.Errorf("missing job ID in injected consensus tx")
	}
	if len(tx.OutputHash) != 32 {
		return fmt.Errorf("invalid output hash length in injected consensus tx")
	}
	if tx.ValidatorCount < 0 || tx.TotalVotes < 0 || tx.AgreementPower < 0 || tx.TotalPower < 0 {
		return fmt.Errorf("negative consensus evidence values are not allowed")
	}
	if tx.ValidatorCount > tx.TotalVotes {
		return fmt.Errorf("validator count exceeds total votes: %d > %d", tx.ValidatorCount, tx.TotalVotes)
	}
	return nil
}

func validateConsensusEvidenceThreshold(
	validatorCount, totalVotes int,
	agreementPower, totalPower int64,
	consensusThreshold int,
	allowVoteFallback bool,
) error {
	if totalPower > 0 {
		requiredPower := requiredConsensusPower(totalPower, consensusThreshold)
		if agreementPower < requiredPower {
			return fmt.Errorf("insufficient validator power consensus: got %d, need %d", agreementPower, requiredPower)
		}
		return nil
	}

	if !allowVoteFallback {
		return fmt.Errorf("missing total voting power in injected tx")
	}

	requiredVotes := (totalVotes * consensusThreshold / 100) + 1
	if validatorCount < requiredVotes {
		return fmt.Errorf("insufficient validator consensus: got %d, need %d", validatorCount, requiredVotes)
	}
	return nil
}

func commitVoteTotals(commit abci.CommitInfo) (totalVotes int, totalPower int64) {
	totalVotes = len(commit.Votes)
	for _, vote := range commit.Votes {
		totalPower += vote.Validator.Power
	}
	return totalVotes, totalPower
}

func validateInjectedConsensusEvidenceAgainstCommit(txBytes []byte, commit abci.CommitInfo, consensusThreshold int) error {
	tx, err := parseInjectedConsensusTx(txBytes)
	if err != nil {
		return err
	}

	commitVotes, commitPower := commitVoteTotals(commit)
	if tx.TotalVotes != commitVotes {
		return fmt.Errorf("injected total votes mismatch: tx=%d commit=%d", tx.TotalVotes, commitVotes)
	}
	if tx.TotalPower != commitPower {
		return fmt.Errorf("injected total power mismatch: tx=%d commit=%d", tx.TotalPower, commitPower)
	}

	requiredPower := requiredConsensusPower(tx.TotalPower, consensusThreshold)
	if tx.TotalPower <= 0 || tx.AgreementPower < requiredPower {
		return fmt.Errorf("injected agreement power below threshold: got %d need %d", tx.AgreementPower, requiredPower)
	}
	return nil
}

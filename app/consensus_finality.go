package app

import (
	"bytes"
	"fmt"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func (app *AethelredApp) validateComputationFinality(results map[string]*pouwkeeper.AggregatedResult, txs [][]byte, consensusThreshold int) error {
	consensusJobs := make(map[string]*pouwkeeper.AggregatedResult)
	for _, res := range results {
		if res == nil || !res.HasConsensus {
			continue
		}
		requiredPower := requiredConsensusPower(res.TotalPower, consensusThreshold)
		if res.TotalPower <= 0 || res.AgreementPower < requiredPower {
			return fmt.Errorf("consensus evidence below threshold for job %s", res.JobID)
		}
		consensusJobs[res.JobID] = res
	}

	injected := make(map[string]*InjectedVoteExtensionTx)
	for _, txBytes := range txs {
		if !IsInjectedVoteExtensionTx(txBytes) {
			continue
		}
		tx, err := parseInjectedConsensusTx(txBytes)
		if err != nil {
			return err
		}
		if _, exists := injected[tx.JobID]; exists {
			return fmt.Errorf("duplicate injected consensus tx for job %s", tx.JobID)
		}
		injected[tx.JobID] = tx
	}

	for jobID, res := range consensusJobs {
		inj, ok := injected[jobID]
		if !ok {
			return fmt.Errorf("missing injected consensus tx for job %s", jobID)
		}
		if !bytes.Equal(inj.OutputHash, res.OutputHash) {
			return fmt.Errorf("output hash mismatch for job %s", jobID)
		}
		requiredPower := requiredConsensusPower(inj.TotalPower, consensusThreshold)
		if inj.TotalPower <= 0 || inj.AgreementPower < requiredPower {
			return fmt.Errorf("injected consensus tx below power threshold for job %s", jobID)
		}
		if inj.TotalPower != res.TotalPower || inj.AgreementPower != res.AgreementPower {
			return fmt.Errorf("injected consensus power mismatch for job %s", jobID)
		}
		if inj.ValidatorCount != res.AgreementCount || inj.TotalVotes != res.TotalVotes {
			return fmt.Errorf("injected consensus vote-count mismatch for job %s", jobID)
		}
	}

	for jobID, inj := range injected {
		res, ok := consensusJobs[jobID]
		if !ok || res == nil || !res.HasConsensus {
			return fmt.Errorf("injected consensus tx without quorum for job %s", jobID)
		}
		if !bytes.Equal(inj.OutputHash, res.OutputHash) {
			return fmt.Errorf("output hash mismatch for job %s", jobID)
		}
	}

	return nil
}
